"""
orchestrator/baseliner.py — per-entity statistical baselining.

WHY THIS EXISTS
---------------
A fixed threshold ("alert if 4625 count >= 12 in 5 min") is the #1 source of both
false positives AND false negatives in production:
  - a busy auth server normally sees 40 failures/5min  -> the rule screams all day
  - a quiet finance workstation sees 2 normally        -> 8 failures (a real spray)
    never reaches 12 and sails through.

The fix every mature SOC uses is BASELINING: learn each entity's own normal, then
alert on DEVIATION from that entity's baseline, not an absolute number.

We use the MODIFIED Z-SCORE (Iglewicz & Hoaglin, 1993, "How to Detect and Handle
Outliers", ASQC Basic References in Quality Control):

    M_i = 0.6745 * (x_i - median) / MAD,   MAD = median(|x_i - median|)

MAD (median absolute deviation) is used instead of mean/stdev because it is robust:
a few huge attack spikes in the training window won't inflate the baseline and hide
the next attack. |M_i| > 3.5 is the standard outlier cutoff.

Entities with too little history fall back to a POOLED global baseline so a
brand-new user is judged against the population, not auto-flagged or auto-ignored.

`to_spl()` emits the equivalent production Splunk query (per-entity eventstats), so
this is not just an in-arena scorer — it's the detection you would actually deploy.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass, field

# Iglewicz-Hoaglin constant (0.6745 = 0.75 quantile of the standard normal); the
# conventional modified z-score cutoff for an outlier.
_MAD_SCALE = 0.6745
_DEFAULT_CUTOFF = 3.5


@dataclass
class EntityStat:
    median: float
    mad: float
    mean: float
    stdev: float
    n: int


@dataclass
class EntityBaseliner:
    """
    Learns a per-entity distribution of some scalar metric (e.g. failed-logon count
    per 5-min bucket per user) and scores new observations by deviation.

    Args:
        cutoff: |modified z| above this is anomalous (default 3.5).
        min_observations: entities with fewer samples use the pooled global baseline.
    """
    cutoff: float = _DEFAULT_CUTOFF
    min_observations: int = 5
    _stats: dict[str, EntityStat] = field(default_factory=dict)
    _global: EntityStat | None = None

    # ── fit ─────────────────────────────────────────────────────────────────────
    def fit(self, observations: dict[str, list[float]]) -> "EntityBaseliner":
        """observations: {entity: [metric samples]}. Builds per-entity + global stats."""
        pooled: list[float] = []
        for entity, samples in observations.items():
            vals = [float(s) for s in samples]
            if not vals:
                continue
            pooled.extend(vals)
            self._stats[entity] = self._compute(vals)
        if pooled:
            self._global = self._compute(pooled)
        return self

    @staticmethod
    def _compute(vals: list[float]) -> EntityStat:
        med = statistics.median(vals)
        mad = statistics.median([abs(v - med) for v in vals]) if len(vals) > 1 else 0.0
        mean = statistics.fmean(vals)
        stdev = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        return EntityStat(median=med, mad=mad, mean=mean, stdev=stdev, n=len(vals))

    # ── score ───────────────────────────────────────────────────────────────────
    def modified_z(self, entity: str, value: float) -> float:
        """Robust deviation score for `value` against `entity`'s baseline."""
        stat = self._baseline_for(entity)
        if stat is None:
            return 0.0  # nothing learned yet — can't judge
        value = float(value)
        if stat.mad > 0:
            return _MAD_SCALE * (value - stat.median) / stat.mad
        # MAD collapses when >50% of samples are identical. Fall back to classic z.
        if stat.stdev > 0:
            return (value - stat.mean) / stat.stdev
        # Degenerate baseline (all samples identical): any departure is anomalous.
        return 0.0 if value == stat.median else float("inf") if value > stat.median else float("-inf")

    def is_anomalous(self, entity: str, value: float) -> bool:
        return abs(self.modified_z(entity, value)) > self.cutoff

    def _baseline_for(self, entity: str) -> EntityStat | None:
        stat = self._stats.get(entity)
        if stat is not None and stat.n >= self.min_observations:
            return stat
        return self._global if self._global is not None else stat

    # ── production translation ───────────────────────────────────────────────────
    def to_spl(self, index: str, metric_field: str, entity_field: str,
               eventcode: int = 4625, span: str = "5m") -> str:
        """
        Emit the equivalent per-entity baselining query for Splunk. Uses avg/stdev
        (native Splunk functions) for the deployable rule; the Python scorer above
        uses MAD for robustness in-arena. The cutoff is expressed in sigmas.
        """
        return (
            f"index={index} EventCode={eventcode}\n"
            f"| bin _time span={span}\n"
            f"| stats count as {metric_field} by {entity_field}, _time\n"
            f"| eventstats avg({metric_field}) as baseline_avg, "
            f"stdev({metric_field}) as baseline_stdev by {entity_field}\n"
            f"| eval zscore = ({metric_field} - baseline_avg) / "
            f"(baseline_stdev + 0.0001)\n"
            f"| where zscore > {self.cutoff}\n"
            f"| eval anomaly_kind=\"per_entity_baseline_deviation\""
        )

    def summary(self) -> dict:
        return {
            "entities_learned": len(self._stats),
            "global_median": round(self._global.median, 2) if self._global else None,
            "global_mad": round(self._global.mad, 2) if self._global else None,
        }
