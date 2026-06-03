"""
SQLite-backed checkpoint and replay for PurpleForge arena runs.

Allows:
  - Resuming a crashed/interrupted arena from the last completed round
  - Replaying a past run for debugging
  - Storing per-round state (injected events, detection results, mutations)
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "results" / "arena.db"


def _get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn


def _init_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id    TEXT PRIMARY KEY,
            started   TEXT NOT NULL,
            config    TEXT NOT NULL,
            status    TEXT NOT NULL DEFAULT 'running'
        );

        CREATE TABLE IF NOT EXISTS rounds (
            run_id    TEXT NOT NULL,
            round_num INTEGER NOT NULL,
            completed TEXT,
            injected  TEXT,   -- JSON: {technique_id: [events]}
            detected  TEXT,   -- JSON: {technique_id: bool}
            catching  TEXT,   -- JSON: {technique_id: rule_name}
            coverage  REAL,
            PRIMARY KEY (run_id, round_num)
        );

        CREATE TABLE IF NOT EXISTS mutations (
            run_id       TEXT NOT NULL,
            round_num    INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            overrides    TEXT NOT NULL,  -- JSON dict
            PRIMARY KEY (run_id, round_num, technique_id)
        );

        CREATE TABLE IF NOT EXISTS rule_provenance (
            run_id       TEXT NOT NULL,
            round_num    INTEGER NOT NULL,
            technique_id TEXT NOT NULL,
            child_rule   TEXT NOT NULL,  -- generated rule name
            parent_rule  TEXT,           -- rule red was evading (NULL = first miss)
            mutation     TEXT,           -- JSON: what red changed to force this rule
            PRIMARY KEY (run_id, child_rule)
        );
    """)
    conn.commit()


class Checkpoint:
    """Context manager for arena run checkpointing."""

    def __init__(self, config: dict):
        self.conn = _get_conn()
        self.run_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        # Store sanitized config (no credentials)
        safe_cfg = {"arena": config.get("arena", {}), "llm": {"provider": config.get("llm", {}).get("provider")}}
        self.conn.execute(
            "INSERT INTO runs (run_id, started, config, status) VALUES (?, ?, ?, 'running')",
            (self.run_id, datetime.now().isoformat(), json.dumps(safe_cfg)),
        )
        self.conn.commit()

    def save_round(
        self,
        round_num: int,
        injected: dict,
        detected: dict,
        catching_rules: dict,
        coverage: float,
        mutations: dict,
    ) -> None:
        """Persist a completed round's state."""
        # Serialize injected events (drop internal _time field to keep DB small)
        injected_slim = {
            tid: [{k: v for k, v in ev.items() if k != "_time"} for ev in evs]
            for tid, evs in injected.items()
        }
        self.conn.execute(
            """INSERT OR REPLACE INTO rounds
               (run_id, round_num, completed, injected, detected, catching, coverage)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                self.run_id, round_num,
                datetime.now().isoformat(),
                json.dumps(injected_slim),
                json.dumps(detected),
                json.dumps(catching_rules),
                coverage,
            ),
        )
        for tid, overrides in mutations.items():
            if overrides:
                self.conn.execute(
                    "INSERT OR REPLACE INTO mutations (run_id, round_num, technique_id, overrides) VALUES (?, ?, ?, ?)",
                    (self.run_id, round_num, tid, json.dumps(overrides)),
                )
        self.conn.commit()

    def save_rule_provenance(
        self,
        round_num: int,
        technique_id: str,
        child_rule: str,
        parent_rule: str | None,
        mutation: dict | None,
    ) -> None:
        """Track the parent→child rule lineage (the AI learning chain)."""
        self.conn.execute(
            """INSERT OR REPLACE INTO rule_provenance
               (run_id, round_num, technique_id, child_rule, parent_rule, mutation)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (
                self.run_id, round_num, technique_id,
                child_rule, parent_rule,
                json.dumps(mutation) if mutation else None,
            ),
        )
        self.conn.commit()

    def mark_complete(self) -> None:
        self.conn.execute("UPDATE runs SET status='complete' WHERE run_id=?", (self.run_id,))
        self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def get_last_completed_round(self) -> int:
        """Return the highest completed round number for this run, or 0 if none."""
        row = self.conn.execute(
            "SELECT MAX(round_num) as r FROM rounds WHERE run_id=?", (self.run_id,)
        ).fetchone()
        return row["r"] or 0

    @staticmethod
    def list_runs() -> list[dict]:
        """List all past runs."""
        conn = _get_conn()
        rows = conn.execute("SELECT run_id, started, status FROM runs ORDER BY started DESC").fetchall()
        return [dict(r) for r in rows]
