"""
orchestrator/engine.py — the REAL-TIME, adaptive arena.

WHY THIS EXISTS
---------------
main.py runs a turn-based loop: Red injects everything, Blue detects everything,
score, repeat. Clean for a demo, but it is not how an attacker and defender
actually race. In reality, whoever completes their OODA loop (Observe-Orient-
Decide-Act) first acts — and acts again — without waiting for the other side.

This engine models exactly that. It runs THREE independent asyncio loops:

  * red_loop   — keeps attacking. When Blue catches a technique, Red immediately
                 mutates it to evade (escalation), acting on a SHORTER cadence
                 because it just took a hit. "Hacker finds a way around the wall."
  * blue_loop  — keeps sweeping recent events. When a technique slips past every
                 rule for longer than a grace window, Blue authors a brand-new
                 Sigma detection on the fly and the very next sweep uses it.
                 "Protector patches the wall." Misses make Blue act sooner too.
  * metrics_loop — periodically snapshots coverage, prints a live scoreboard, and
                 ships a summary event to Splunk so the dashboard moves in real time.

ADAPTIVE, NOT TURN-BASED
------------------------
Each loop sleeps on its own clock and SHORTENS that sleep after a setback, so a
fast mover gets to act more often than a slow one — "if one model finds a hack
quicker than the other it can run that as well." There are no turns.

CONCURRENCY MODEL
-----------------
Every Splunk/LLM call in the codebase is blocking (requests + blocking LLM I/O).
Each such call is pushed onto a worker thread with asyncio.to_thread, so the two
agent loops make genuine concurrent progress. Shared ArenaState is mutated only
inside the event loop (never in the worker threads) and guarded by an asyncio
lock around each read-modify-write span, with the long I/O done OUTSIDE the lock.

EVASION MEASUREMENT (honest)
----------------------------
Every injected event is stamped with arena_generation (Red's mutation counter).
Blue's rules never look at it — detection stays realistic. But for METRICS we
inspect which generations actually appear in the firing rows: if Blue's hits are
only stale prior-generation events and the newest generation is absent, Red has
genuinely evaded. Aggregation rules (e.g. password-spray) don't carry per-event
fields, so a firing aggregation rule is conservatively credited with the current
generation rather than over-claiming an evasion.
"""
from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.table import Table

from orchestrator.scorer import score_round, score_precision, check_win, _infer_technique_from_rule_name
from orchestrator import memory as arena_memory
from red_agent.benign import BenignGenerator
from blue_agent.mutation_inferencer import MutationInferencer
from mitre.techniques import TECHNIQUES

console = Console()


@dataclass
class TechniqueState:
    """Live state for a single technique in the arms race."""
    tid: str
    generation: int = 0              # bumps every time Red mutates this technique
    inject_ts: float | None = None   # wall time the CURRENT generation was injected
    last_events: list = field(default_factory=list)  # sample of current-gen events
    detected: bool = False           # is the CURRENT generation caught right now?
    catching_rule: str | None = None
    rule_generated_for_gen: bool = False  # has Blue already authored a rule for this gen?
    compromised: bool = False         # rule was burned → technique evaded + covered rule gone
    poison_events: int = 0            # FP events Red injected for this technique
    # Kill-chain objective tracking
    objective: str = ""               # human-readable attack goal from template
    dwell_threshold: float = 60.0     # seconds undetected before objective is achieved
    objective_achieved: bool = False  # Red dwelled long enough — mission succeeded
    objective_achieved_at: float | None = None
    undetected_since: float | None = None  # wall time current gen became undetected
    # metrics
    detect_latencies: list[float] = field(default_factory=list)  # one per caught generation
    evasions: int = 0                # mutated generations that survived the grace window
    survival_times: list[float] = field(default_factory=list)    # how long each evasion lasted
    rules_generated: int = 0
    times_caught: int = 0
    last_mutation: dict = field(default_factory=dict)   # Option C: fields Red changed on last mutation


class RealTimeEngine:
    """
    Concurrent Red/Blue/metrics loops sharing one ArenaState. Reuses the agents,
    clients, coverage matrix, and config already built by the Orchestrator — this
    is a different way to DRIVE the same pieces, not a reimplementation.
    """

    def __init__(self, orch, duration: float = 90.0):
        self.orch = orch
        self.red = orch.red
        self.blue = orch.blue
        self.hec = orch.hec
        self.coverage = orch.coverage
        self.index = orch.index_attacks
        self.duration = duration

        rt = orch.cfg.get("arena", {}).get("realtime", {})
        self.red_base = float(rt.get("red_base_seconds", 6.0))
        self.red_urgent = float(rt.get("red_urgent_seconds", 2.5))
        self.blue_base = float(rt.get("blue_base_seconds", 4.0))
        self.blue_urgent = float(rt.get("blue_urgent_seconds", 2.0))
        self.window_seconds = int(rt.get("window_seconds", 120))
        self.evasion_grace = float(rt.get("evasion_grace_seconds", 5.0))   # Option A: was 12s
        self.metrics_every = float(rt.get("metrics_every_seconds", 8.0))
        self.benign_every = float(rt.get("benign_every_seconds", 12.0))
        self.inject_benign = orch.cfg.get("arena", {}).get("benign", True)
        self.benign = BenignGenerator(self.hec, self.index)

        # RuleRegistry — shared with Blue agent (may be None if not configured)
        self.registry = getattr(orch, "registry", None)

        # Win condition thresholds (from Orchestrator config)
        self.blue_win_threshold = getattr(orch, "blue_win_threshold", 70.0)
        self.red_win_threshold  = getattr(orch, "red_win_threshold",  60.0)

        # Poison campaign cadence (seconds between FP floods)
        self._poison_interval = float(rt.get("poison_interval_seconds", 15.0))

        # Track 5 — mutation inference (the moat). When True, Blue INFERS Red's
        # field changes by diffing evading events against the last batch it caught,
        # instead of being handed Red's overrides. Production-realistic: a real
        # attacker never confesses. Default False so the demo loop is unchanged.
        self.infer_mutations = bool(rt.get("infer_mutations", False))
        self.mutation_inferencer = MutationInferencer()

        self.techniques = list(self.red.technique_ids)
        self.state: dict[str, TechniqueState] = {}
        for t in self.techniques:
            td = self.red.templates.get(t, {})
            hints = td.get("mutation_hints", {})
            self.state[t] = TechniqueState(
                tid=t,
                objective=hints.get("objective", f"Execute {t}"),
                dwell_threshold=float(hints.get("dwell_threshold_seconds", 60.0)),
            )
        self.lock = asyncio.Lock()
        self.stop = asyncio.Event()
        self.t0 = 0.0
        self.action_seq = 0           # monotonic id for injection batches (-> arena_round)
        self.event_log: list[dict] = []  # human-readable trace for the final report
        self._rr = 0                  # round-robin pointer for Red's "keep pressure" picks
        # precision tracking (latest sweep snapshot)
        self.overall_precision: float | None = None
        self.rule_fp: dict[str, int] = {}  # rule_name -> cumulative benign hits seen
        # rule-burn / compromise tracking
        self._compromised_count: int = 0
        self._rules_burned_total: int = 0
        self._winner: str | None = None
        self._red_cooldown: dict[str, float] = {}   # Option F: tid -> wall time of last mutation
        # kill-chain objective tracking
        self._objectives_achieved: int = 0

    # ── helpers ───────────────────────────────────────────────────────────────
    def _elapsed(self) -> float:
        return time.monotonic() - self.t0

    def _log(self, side: str, msg: str, color: str) -> None:
        t = self._elapsed()
        console.print(f"[dim]\\[t+{t:5.1f}s][/dim] [{color}]{side:<5}[/{color}] {msg}")
        self.event_log.append({"t": round(t, 2), "side": side, "msg": msg})

    def _earliest(self) -> str:
        return f"-{self.window_seconds}s"

    def _mutation_context(self, tid: str, events: list[dict]) -> dict[str, dict]:
        """
        Mutation overrides to feed Blue's rule generator for `tid`, shaped as
        {tid: {field: new_value}} — exactly what generate_rules_for_misses expects.

        Inference mode (production-realistic): Blue EARNS the knowledge by diffing
        the evading events against the last batch it caught; the attacker never tells
        us. Arena mode: use Red's self-reported overrides (the demo default).
        """
        if self.infer_mutations:
            return {tid: self.mutation_inferencer.infer_mutation(tid, events)}
        return self.red.get_current_overrides()

    # ── RED ─────────────────────────────────────────────────────────────────────
    async def red_loop(self) -> None:
        """Attack, observe outcomes, and escalate (mutate) the moment Blue catches up."""
        while not self.stop.is_set():
            async with self.lock:
                never = [t for t in self.techniques if self.state[t].inject_ts is None]
                _now = time.monotonic()
                # Option F: only escalate a caught technique once its 30s cooldown has elapsed,
                # so Blue gets a real opportunity to author a rule before Red mutates again.
                burned = [
                    t for t in self.techniques
                    if self.state[t].detected
                    and _now - self._red_cooldown.get(t, 0) >= 30.0
                ]
                if never:
                    target, action = never[0], "inject"
                elif burned:
                    # Escalate the technique that has been caught the longest-running.
                    target, action = burned[0], "mutate"
                else:
                    # Keep pressure: refresh the stalest technique so its events stay
                    # inside Blue's sliding window (round-robin to vary the target).
                    self._rr = (self._rr + 1) % len(self.techniques)
                    target, action = self.techniques[self._rr], "inject"

            urgent = (action == "mutate")
            await self._red_act(target, action)

            await self._sleep(self.red_urgent if urgent else self.red_base)

    async def _red_act(self, tid: str, action: str) -> None:
        meta = TECHNIQUES.get(tid, {"name": tid})
        self.action_seq += 1
        seq = self.action_seq

        if action == "mutate":
            st = self.state[tid]
            catching_spl = self.blue.get_catching_rule_for(tid)
            await asyncio.to_thread(self.red.receive_catching_rule, tid, catching_spl or "")
            new_gen = st.generation + 1
            events = await asyncio.to_thread(self.red.inject_technique, tid, seq, new_gen)
            # Fetch overrides BEFORE the lock — receive_catching_rule already applied them.
            mut = self.red.get_current_overrides().get(tid) or {}
            async with self.lock:
                st.generation = new_gen
                st.inject_ts = time.monotonic()
                st.last_events = events
                st.detected = False
                st.rule_generated_for_gen = False
                st.undetected_since = time.monotonic()   # fresh evasion window starts
                st.last_mutation = dict(mut)             # Option C: record what changed
                self._red_cooldown[tid] = time.monotonic()  # Option F: start escalation cooldown
            changed = ", ".join(mut.keys()) if mut else "timing/values"
            self._log("RED", f"MUTATE {tid} ({meta['name']}) gen{new_gen} — evading via [{changed}]", "red")
        else:
            st = self.state[tid]
            first = st.inject_ts is None
            events = await asyncio.to_thread(self.red.inject_technique, tid, seq, st.generation)
            async with self.lock:
                st.inject_ts = time.monotonic()
                st.last_events = events
                if first:
                    st.detected = False
                    st.undetected_since = time.monotonic()  # objective clock starts on first inject
            verb = "INJECT" if first else "refresh"
            self._log("RED", f"{verb} {tid} ({meta['name']}) gen{st.generation} — {len(events)} events", "red")

    # ── BENIGN NOISE ──────────────────────────────────────────────────────────────
    async def benign_loop(self) -> None:
        """Keep a steady drip of legitimate activity flowing so precision stays measurable."""
        if not self.inject_benign:
            return
        while not self.stop.is_set():
            events = await asyncio.to_thread(self.benign.inject, self.action_seq)
            self._log("NOISE", f"{len(events)} benign events injected", "dim")
            await self._sleep(self.benign_every)

    # ── RED POISON ───────────────────────────────────────────────────────────────
    async def poison_loop(self) -> None:
        """Periodically flood Blue's catching rules with FP events (alert fatigue)."""
        while not self.stop.is_set():
            await self._sleep(self._poison_interval)
            if self.stop.is_set():
                break
            results = await asyncio.to_thread(
                self.red.run_poison_campaign, self.action_seq, 5
            )
            if results:
                total = sum(results.values())
                async with self.lock:
                    for tid, n in results.items():
                        if tid in self.state:
                            self.state[tid].poison_events += n
                self._log("RED", f"POISON: {total} FP events across {len(results)} rule(s)", "red")

    # ── BLUE ─────────────────────────────────────────────────────────────────────
    async def blue_loop(self) -> None:
        """Sweep recent events; catch what we can; author a new rule for anything slipping past."""
        while not self.stop.is_set():
            had_miss = await self._blue_sweep()
            await self._sleep(self.blue_urgent if had_miss else self.blue_base)

    async def _blue_sweep(self) -> bool:
        # 1. Run every rule over the sliding window (off-thread; reloads rules from disk,
        #    so any rule Blue just generated is live this sweep).
        results = await asyncio.to_thread(
            self.blue.run_detection, self._earliest(), "now"
        )
        detected, catching = score_round(
            injected={t: [] for t in self.techniques},  # technique list only; rows carry the truth
            detection_results=results,
            technique_ids=self.techniques,
        )

        # Precision snapshot: how much of what each rule fired on was benign?
        overall_prec, rule_prec = score_precision(results)

        # Registry: record precision per rule, detect newly burned rules.
        newly_burned: list[str] = []
        if self.registry is not None:
            newly_burned = self.registry.record_batch(rule_prec, self.action_seq)
            for rule_name in newly_burned:
                inferred_tid = _infer_technique_from_rule_name(rule_name)
                async with self.lock:
                    self._rules_burned_total += 1
                    if inferred_tid and inferred_tid in self.state:
                        self.state[inferred_tid].compromised = True
                        self._compromised_count += 1
                self.blue.notify_rule_burned(inferred_tid or "")
                self.red.stop_poisoning(inferred_tid or "")
                self._log(
                    "BLUE",
                    f"RULE BURNED: '{rule_name}' (precision collapsed) "
                    f"→ {inferred_tid or '?'} COMPROMISED",
                    "red",
                )

        # Handle Blue's burned-rule replacement queue (generate new rules for compromised techniques)
        burned_replacements = self.blue.pop_burned_replacement_queue()
        for tid in burned_replacements:
            async with self.lock:
                events = list(self.state[tid].last_events) if tid in self.state else []
            if events:
                await asyncio.to_thread(
                    self.blue.generate_rules_for_misses,
                    {tid: events}, self.action_seq, self._mutation_context(tid, events),
                )
                self._log("BLUE", f"REPLACEMENT rule generated for COMPROMISED {tid}", "blue")

        to_generate: list[str] = []
        objective_log: list[tuple[str, str, float]] = []  # (tid, objective, dwell) — log after lock
        async with self.lock:
            self.overall_precision = overall_prec
            for name, p in rule_prec.items():
                if p["fp"] > 0:
                    self.rule_fp[name] = max(self.rule_fp.get(name, 0), p["fp"])
            for tid in self.techniques:
                st = self.state[tid]
                if st.inject_ts is None:
                    continue
                cur_gen_hit = self._current_gen_in_rows(tid, st.generation, results)
                now = time.monotonic()

                if cur_gen_hit and not st.detected:
                    # Blue catches this generation — stop the dwell clock, objective BLOCKED.
                    latency = now - st.inject_ts
                    st.detected = True
                    st.times_caught += 1
                    st.detect_latencies.append(latency)
                    st.undetected_since = None  # objective clock stops
                    # Snapshot the caught fingerprint so the inferencer can diff a
                    # future evasion against the last batch we actually detected.
                    if self.infer_mutations and st.last_events:
                        self.mutation_inferencer.record_caught(tid, st.last_events, st.generation)
                    rule_name = catching.get(tid)
                    st.catching_rule = rule_name
                    if rule_name:
                        self.blue.record_catching_rule(tid, rule_name)
                    self._log(
                        "BLUE",
                        f"DETECT {tid} gen{st.generation} in {latency:4.1f}s via '{rule_name}'",
                        "blue",
                    )

                elif not cur_gen_hit:
                    # Technique is evading. Start or advance the dwell clock.
                    # Use `now` (first sweep that observed a miss) rather than
                    # inject_ts, so short thresholds don't fire before Blue has
                    # had a real opportunity to detect.
                    if st.undetected_since is None:
                        st.undetected_since = now

                    dwell = now - st.undetected_since

                    # Check if Red has dwelled long enough to achieve the objective.
                    if not st.objective_achieved and dwell >= st.dwell_threshold:
                        st.objective_achieved = True
                        st.objective_achieved_at = now
                        self._objectives_achieved += 1
                        objective_log.append((tid, st.objective, dwell))

                    # Credit evasion when a MUTATED gen survives the grace window.
                    # BUG FIX: use dwell (from undetected_since) not inject_ts — inject_ts
                    # resets every 2.5s on keep-pressure refreshes, so `age` never exceeds
                    # evasion_grace. dwell only resets when Blue actually detects.
                    if dwell >= self.evasion_grace and not st.rule_generated_for_gen and st.last_events:
                        if st.generation > 0 and not st.detected and st.times_caught > 0:
                            st.evasions += 1
                            st.survival_times.append(dwell)
                            self._log("RED", f"EVADED {tid} gen{st.generation} survived {dwell:4.1f}s", "red")
                        to_generate.append(tid)

        # Log objective achievements outside the lock.
        for tid, obj, dwell in objective_log:
            self._log("RED",
                      f"⚡ OBJECTIVE ACHIEVED: {tid} — '{obj[:55]}' "
                      f"(evaded {dwell:.0f}s / threshold {self.state[tid].dwell_threshold:.0f}s)",
                      "red")

        # 2. Generate rules OUTSIDE the lock (LLM call is slow).
        # Skip generation entirely if the run is already stopping — avoids the
        # arena getting stuck for minutes past its duration on in-flight LLM calls.
        had_miss = bool(to_generate)
        for tid in to_generate:
            if self.stop.is_set():
                break
            await self._blue_generate(tid)
        return had_miss

    async def _blue_generate(self, tid: str) -> None:
        async with self.lock:
            st = self.state[tid]
            events = list(st.last_events)
            gen = st.generation
            st.rule_generated_for_gen = True  # at most one generation attempt per generation
        if not events:
            return
        self._log("BLUE", f"GENERATE rule for missed {tid} gen{gen} ...", "blue")
        mutation_ctx = self._mutation_context(tid, events)
        if self.infer_mutations:
            self._log("BLUE", f"INFERRED Red's change to {tid}: {self.mutation_inferencer.describe(tid, events)}", "blue")
        saved = await asyncio.to_thread(
            self.blue.generate_rules_for_misses,
            {tid: events},
            self.action_seq,
            mutation_ctx,
        )
        async with self.lock:
            if saved:
                self.state[tid].rules_generated += 1
                self.coverage.record_rule_generated(tid)
                self._log("BLUE", f"NEW rule ready for {tid} (now live for next sweep)", "blue")
            else:
                # Generation failed; allow a retry on a later sweep.
                self.state[tid].rule_generated_for_gen = False
                self._log("BLUE", f"rule generation FAILED for {tid} — will retry", "yellow")

    @staticmethod
    def _current_gen_in_rows(tid: str, current_gen: int, results: dict[str, list[dict]]) -> bool:
        """
        True if the CURRENT generation of `tid` appears in any firing rule's rows.
        Aggregation rules drop per-event fields, so a firing rule attributed to tid
        whose rows lack arena_generation is conservatively credited (avoids falsely
        declaring an evasion).
        """
        for rule_name, rows in results.items():
            if not rows:
                continue
            rule_tid = _infer_technique_from_rule_name(rule_name)
            for row in rows:
                row_tid = row.get("technique") or row.get("arena_technique") or rule_tid
                if row_tid != tid:
                    continue
                g = row.get("arena_generation")
                if g is None:
                    return True  # aggregation/no-field rule — credit current gen
                try:
                    if int(g) == current_gen:
                        return True
                except (ValueError, TypeError):
                    continue
        return False

    # ── METRICS ──────────────────────────────────────────────────────────────────
    async def metrics_loop(self) -> None:
        sweep = 0
        while not self.stop.is_set():
            await self._sleep(self.metrics_every)
            if self.stop.is_set():
                break
            sweep += 1
            async with self.lock:
                detected_now = {t: self.state[t].detected for t in self.techniques}
                covered = sum(1 for v in detected_now.values() if v)
                cov_pct = round(100 * covered / len(self.techniques), 1)
                rules = sum(s.rules_generated for s in self.state.values())
                evasions = sum(s.evasions for s in self.state.values())
                prec = self.overall_precision
                compromised = self._compromised_count
                burned_total = self._rules_burned_total
                objectives = self._objectives_achieved
                # Techniques at risk: evading and within 10s of objective threshold
                at_risk = [
                    t for t in self.techniques
                    if not self.state[t].detected
                    and self.state[t].undetected_since is not None
                    and not self.state[t].objective_achieved
                    and (time.monotonic() - self.state[t].undetected_since)
                        >= (self.state[t].dwell_threshold - 10)
                ]
            # keep the coverage matrix / navigator export fed
            self.coverage.record_round(round_num=sweep, results=detected_now)

            # Win condition check — Red can end the run early; Blue wins by surviving.
            winner = check_win(
                coverage_pct=cov_pct,
                compromised_count=compromised,
                total_techniques=len(self.techniques),
                blue_win_threshold=self.blue_win_threshold,
                red_win_threshold=self.red_win_threshold,
                objectives_achieved=objectives,
            )
            if winner == "red" and self._winner is None:
                self._winner = "red"
                obj_pct = round(100 * objectives / len(self.techniques), 1)
                self._log("GAME",
                          f"⚡ RED WINS: {objectives}/{len(self.techniques)} objectives achieved "
                          f"({obj_pct}%) — mission succeeded",
                          "red")
                self.stop.set()
                break
            elif winner == "blue" and self._winner is None:
                self._winner = "blue"
                self._log("GAME",
                          f"🛡  Blue crossed {self.blue_win_threshold:.0f}% threshold "
                          f"({cov_pct}%) — run continues until timer",
                          "blue")

            def_strength = (
                round(self.registry.health_summary()["defense_strength_pct"], 1)
                if self.registry else 100.0
            )
            prec_str = f"{prec:.0%}" if prec is not None else "n/a"
            at_risk_str = f"  ⚠ AT RISK: {at_risk}" if at_risk else ""
            self._log(
                "STAT",
                f"coverage {cov_pct}%  caught {covered}/{len(self.techniques)}  "
                f"objectives {objectives}/{len(self.techniques)} achieved  "
                f"precision {prec_str}  rules+{rules}  evasions {evasions}  "
                f"compromised {compromised}  defense {def_strength}%{at_risk_str}",
                "magenta",
            )
            # live dashboard feed
            try:
                await asyncio.to_thread(
                    self.hec.send_events,
                    [{
                        "event_type": "purpleforge_realtime_status",
                        "t_seconds": round(self._elapsed(), 1),
                        "coverage_pct": cov_pct,
                        "detected_count": covered,
                        "rules_generated": rules,
                        "evasions": evasions,
                        "compromised_count": compromised,
                        "rules_burned_total": burned_total,
                        "defense_strength_pct": def_strength,
                        "precision_pct": round(prec * 100, 1) if prec is not None else None,
                        "detected_techniques": ",".join(t for t, v in detected_now.items() if v),
                        "objectives_achieved": objectives,
                        "objectives_total": len(self.techniques),
                        "winner": self._winner or "",
                    }],
                    self.index,
                    "purpleforge:realtime",
                )
            except Exception as e:
                self._log("STAT", f"(dashboard feed skipped: {e})", "dim")

    # ── lifecycle ─────────────────────────────────────────────────────────────────
    async def _sleep(self, seconds: float) -> None:
        """Sleep, but wake immediately if the run is stopping."""
        try:
            await asyncio.wait_for(self.stop.wait(), timeout=seconds)
        except asyncio.TimeoutError:
            pass

    async def _timer(self) -> None:
        await self._sleep(self.duration)
        self.stop.set()

    async def _run(self) -> None:
        self.t0 = time.monotonic()
        console.print(f"\n[bold magenta]REAL-TIME ARENA[/bold magenta]  "
                      f"duration={self.duration:.0f}s  techniques={len(self.techniques)}  "
                      f"window={self.window_seconds}s\n")
        self.blue.reset_round()
        await asyncio.gather(
            self.red_loop(),
            self.blue_loop(),
            self.benign_loop(),
            self.poison_loop(),
            self.metrics_loop(),
            self._timer(),
        )

    def run(self) -> None:
        self.orch._ensure_indexes()
        try:
            asyncio.run(self._run())
        except KeyboardInterrupt:
            self.stop.set()
            console.print("\n[yellow]Interrupted — writing report.[/yellow]")
        self._finish()

    # ── reporting ─────────────────────────────────────────────────────────────────
    def _finish(self) -> None:
        table = Table(title="Real-Time Arena — Final Scoreboard")
        for col in ("Technique", "Name", "Gen", "State", "Detect (s)",
                    "Evasions", "Rules", "Last Mutation", "FP inj.", "Mission"):
            table.add_column(col, overflow="fold")
        total_lat, n_lat = 0.0, 0
        for tid in self.techniques:
            st = self.state[tid]
            avg_det = (sum(st.detect_latencies) / len(st.detect_latencies)) if st.detect_latencies else None
            if st.detect_latencies:
                total_lat += sum(st.detect_latencies)
                n_lat += len(st.detect_latencies)
            if st.compromised:
                state_str = "[red]COMPROMISED[/red]"
            elif st.detected:
                state_str = "[green]detected[/green]"
            else:
                state_str = "[yellow]evading[/yellow]"
            if st.objective_achieved:
                mission_str = "[bold red]⚡ ACHIEVED[/bold red]"
            elif st.detected and not st.objective_achieved:
                mission_str = "[green]BLOCKED ✓[/green]"
            elif st.inject_ts is None:
                mission_str = "[dim]pending[/dim]"
            else:
                if st.undetected_since:
                    dwell = time.monotonic() - st.undetected_since
                    left = max(0, st.dwell_threshold - dwell)
                    mission_str = f"[yellow]⚠ {left:.0f}s left[/yellow]"
                else:
                    mission_str = "[dim]watching[/dim]"
            mut_str = ", ".join(st.last_mutation.keys())[:28] if st.last_mutation else "-"
            table.add_row(
                tid, TECHNIQUES.get(tid, {}).get("name", tid)[:28], str(st.generation),
                state_str,
                (f"{avg_det:.1f}" if avg_det is not None else "-"),
                str(st.evasions),
                str(st.rules_generated),
                mut_str,
                str(st.poison_events),
                mission_str,
            )
        console.print()
        console.print(table)

        covered = sum(1 for s in self.state.values() if s.detected)
        cov_pct = round(100 * covered / len(self.techniques), 1)
        mean_ttd = round(total_lat / n_lat, 2) if n_lat else None
        rules = sum(s.rules_generated for s in self.state.values())
        evasions = sum(s.evasions for s in self.state.values())
        prec_str = f"{self.overall_precision:.0%}" if self.overall_precision is not None else "n/a"
        def_strength = (
            round(self.registry.health_summary()["defense_strength_pct"], 1)
            if self.registry else 100.0
        )
        objectives_achieved = sum(1 for s in self.state.values() if s.objective_achieved)
        objectives_blocked  = sum(
            1 for s in self.state.values()
            if s.times_caught > 0 and not s.objective_achieved
        )

        # Objective summary table
        obj_table = Table(title="Kill-Chain Objective Summary", show_header=True)
        for col in ("Technique", "Objective", "Threshold", "Mission"):
            obj_table.add_column(col, overflow="fold")
        for tid in self.techniques:
            st = self.state[tid]
            if st.objective_achieved:
                mis = f"[bold red]⚡ ACHIEVED (evaded {st.dwell_threshold:.0f}s)[/bold red]"
            elif st.times_caught > 0:
                mis = f"[green]BLOCKED — detected in {st.detect_latencies[0]:.1f}s[/green]"
            elif st.inject_ts is None:
                mis = "[dim]never injected[/dim]"
            else:
                mis = "[yellow]evading at end[/yellow]"
            obj_table.add_row(
                tid,
                st.objective[:55],
                f"{st.dwell_threshold:.0f}s",
                mis,
            )
        console.print()
        console.print(obj_table)

        if self._winner == "red" or objectives_achieved >= len(self.techniques) * self.red_win_threshold / 100:
            if self._winner is None:
                self._winner = "red"
            obj_pct = round(100 * objectives_achieved / len(self.techniques), 1)
            console.print(
                f"\n[bold red]⚡ RED WINS[/bold red] — {objectives_achieved}/{len(self.techniques)} "
                f"objectives achieved ({obj_pct}%) | {self._compromised_count} rules burned"
            )
        elif self._winner == "blue" or cov_pct >= self.blue_win_threshold:
            if self._winner is None:
                self._winner = "blue"
            console.print(
                f"\n[bold blue]🛡  BLUE WINS[/bold blue] — survived full duration at {cov_pct}% coverage | "
                f"{objectives_blocked}/{len(self.techniques)} objectives blocked"
            )
        else:
            console.print(f"\n[bold]Arena ended — contested ({cov_pct}% coverage, "
                          f"{objectives_achieved} objectives achieved)[/bold]")

        console.print(
            f"[bold]Final coverage {cov_pct}%[/bold]  | mean TTD "
            f"{mean_ttd if mean_ttd is not None else 'n/a'}s | precision {prec_str} | "
            f"rules generated {rules} | evasions {evasions} | "
            f"objectives achieved {objectives_achieved}/{len(self.techniques)} | "
            f"compromised {self._compromised_count} | rules burned {self._rules_burned_total} | "
            f"defense strength {def_strength}%"
        )
        if self.rule_fp:
            console.print("[yellow]Rules with false positives (tighten these):[/yellow]")
            for name, fp in sorted(self.rule_fp.items(), key=lambda x: -x[1]):
                console.print(f"  [dim]FP[/dim] {name}: {fp} benign hit(s)")
        console.print()

        report = {
            "mode": "realtime",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": self.duration,
            "winner": self._winner,
            "final_coverage_pct": cov_pct,
            "mean_time_to_detect_seconds": mean_ttd,
            "final_precision": self.overall_precision,
            "compromised_count": self._compromised_count,
            "rules_burned_total": self._rules_burned_total,
            "defense_strength_pct": def_strength,
            "objectives_achieved": objectives_achieved,
            "objectives_blocked": objectives_blocked,
            "rules_with_false_positives": self.rule_fp,
            "rules_generated": rules,
            "evasions": evasions,
            "techniques": {
                tid: {
                    "name": TECHNIQUES.get(tid, {}).get("name", tid),
                    "generation": st.generation,
                    "game_state": ("COMPROMISED" if st.compromised
                                   else "DETECTED" if st.detected else "EVADING"),
                    "objective": st.objective,
                    "dwell_threshold_seconds": st.dwell_threshold,
                    "objective_achieved": st.objective_achieved,
                    "times_caught": st.times_caught,
                    "detect_latencies": [round(x, 2) for x in st.detect_latencies],
                    "evasions": st.evasions,
                    "survival_times": [round(x, 2) for x in st.survival_times],
                    "rules_generated": st.rules_generated,
                    "poison_events_injected": st.poison_events,
                    "catching_rule": st.catching_rule,
                    "last_mutation_fields": list(st.last_mutation.keys()),  # Option C
                }
                for tid, st in self.state.items()
            },
            "event_log": self.event_log,
        }
        results_dir = Path(__file__).parent.parent / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        out = results_dir / f"realtime_report_{ts}.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        console.print(f"[dim]Real-time report saved: {out}[/dim]")

        # Persist cross-session memory so the next run starts from the best known state.
        try:
            mem = arena_memory.load()
            arena_memory.save_registry(mem, self.registry)
            # Record any new evasions Red discovered in this session.
            for tid, st in self.state.items():
                if st.evasions > 0:
                    overrides = self.red.get_current_overrides().get(tid, {})
                    arena_memory.record_red_evasion(mem, tid, overrides)
            arena_memory.record_session(
                mem,
                run_id=ts,
                coverage_end=cov_pct,
                rules_generated=rules,
                rules_burned=self._rules_burned_total,
                compromised_techniques=[t for t, s in self.state.items() if s.compromised],
                winner=self._winner or "contested",
            )
            arena_memory.save(mem)
            console.print("[dim]Cross-session memory updated.[/dim]")
        except Exception as e:
            console.print(f"[dim](memory save skipped: {e})[/dim]")

        # Same visual artifact as turn mode: an ATT&CK Navigator coverage layer,
        # built from the matrix the metrics loop fed each tick.
        try:
            from mitre.navigator import export_navigator_layer
            nav = export_navigator_layer(self.coverage.summary(), output_dir=str(results_dir))
            console.print(f"[dim]ATT&CK Navigator layer: {nav}[/dim]")
        except Exception as e:
            console.print(f"[dim](navigator export skipped: {e})[/dim]")
