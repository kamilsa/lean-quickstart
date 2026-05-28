"""SQLite storage for the Shadow fuzzer dashboard."""

from __future__ import annotations

import json
import math
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from dashboard_events import event_key, events_from_run
from dashboard_time import chain_slot_from_simulated_seconds


TERMINAL_STATUSES = {"complete", "warning", "error"}
TRANSIENT_STATS_WARNING_PREFIXES = (
    "shadow.data/hosts directory not found",
    "No propagation events found",
)


SCHEMA = """
PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT UNIQUE NOT NULL,
    run_index INTEGER,
    seed INTEGER,
    status TEXT NOT NULL,
    stage TEXT NOT NULL,
    run_dir TEXT NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    ended_at TEXT,
    duration_secs REAL,
    simulated_seconds REAL NOT NULL DEFAULT 0,
    wall_seconds REAL NOT NULL DEFAULT 0,
    current_slot INTEGER NOT NULL DEFAULT 0,
    progress REAL NOT NULL DEFAULT 0,
    warnings TEXT NOT NULL DEFAULT '[]',
    error TEXT,
    metadata TEXT NOT NULL DEFAULT '{}',
    stats TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    event_key TEXT UNIQUE NOT NULL,
    ts_ms REAL NOT NULL DEFAULT 0,
    kind TEXT NOT NULL,
    host TEXT,
    slot INTEGER,
    message TEXT NOT NULL,
    payload TEXT NOT NULL DEFAULT '{}',
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES runs(run_id)
);

CREATE INDEX IF NOT EXISTS idx_runs_updated ON runs(updated_at);
CREATE INDEX IF NOT EXISTS idx_runs_status ON runs(status);
CREATE INDEX IF NOT EXISTS idx_events_run_id ON events(run_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_slot ON events(slot);
CREATE INDEX IF NOT EXISTS idx_events_host ON events(host);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _json_dumps(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _json_loads(value: str | None, fallback: Any) -> Any:
    if not value:
        return fallback
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return fallback


def _is_transient_stats_warning(warning: str) -> bool:
    return any(
        warning.startswith(prefix)
        for prefix in TRANSIENT_STATS_WARNING_PREFIXES
    )


def _metadata_run_index(metadata: dict[str, Any]) -> int | None:
    if isinstance(metadata.get("run_index"), int):
        return int(metadata["run_index"])
    fuzzer = metadata.get("fuzzer", {})
    if isinstance(fuzzer, dict) and fuzzer.get("run_index") is not None:
        return int(fuzzer["run_index"])
    return None


def _metadata_seed(metadata: dict[str, Any]) -> int | None:
    fuzzer = metadata.get("fuzzer", {})
    if isinstance(fuzzer, dict) and fuzzer.get("seed") is not None:
        return int(fuzzer["seed"])
    if metadata.get("seed") is not None:
        return int(metadata["seed"])
    return None


def _metadata_duration(metadata: dict[str, Any]) -> float | None:
    fuzzer = metadata.get("fuzzer", {})
    if isinstance(fuzzer, dict) and fuzzer.get("duration_secs") is not None:
        return float(fuzzer["duration_secs"])
    return None


def initial_stats_from_metadata(metadata: dict[str, Any], warnings: list[str] | None = None) -> dict[str, Any]:
    warning_list = list(warnings or [])
    return {
        "blocks": {"slots": [], "summary": {"warning": "no block data indexed yet"}},
        "chain_status": {
            "slots": [],
            "summary": {"warning": "no chain status data indexed yet"},
        },
        "attestations": {
            "slots": [],
            "summary": {"warning": "no attestation data indexed yet"},
            "coverage": {
                "target_attestation_coverage": 0.95,
                "node_percentiles": [0.5, 0.9, 0.95],
                "slots": [],
                "summary": {"warning": "no attestation data indexed yet"},
            },
        },
        "event_counts": {},
        "node_distribution": {
            "clients": metadata.get("node_counts", {}),
            "regions": {},
            "bandwidths": {},
        },
        "warnings": warning_list,
        **metadata,
    }


class DashboardDB:
    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _row_to_run(self, row: sqlite3.Row) -> dict[str, Any]:
        metadata = _json_loads(row["metadata"], {})
        stats = _json_loads(row["stats"], {})
        warnings = _json_loads(row["warnings"], [])
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "run_index": row["run_index"],
            "seed": row["seed"],
            "status": row["status"],
            "stage": row["stage"],
            "run_dir": row["run_dir"],
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "ended_at": row["ended_at"],
            "duration_secs": row["duration_secs"],
            "simulated_seconds": row["simulated_seconds"],
            "wall_seconds": row["wall_seconds"],
            "current_slot": row["current_slot"],
            "progress": row["progress"],
            "warnings": warnings,
            "error": row["error"],
            "metadata": metadata,
            "stats": stats,
        }

    def _summary_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        warnings = _json_loads(row["warnings"], [])
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "run_index": row["run_index"],
            "seed": row["seed"],
            "status": row["status"],
            "stage": row["stage"],
            "started_at": row["started_at"],
            "updated_at": row["updated_at"],
            "ended_at": row["ended_at"],
            "duration_secs": row["duration_secs"],
            "simulated_seconds": row["simulated_seconds"],
            "wall_seconds": row["wall_seconds"],
            "current_slot": row["current_slot"],
            "progress": row["progress"],
            "warnings": warnings,
            "error": row["error"],
        }

    def start_run(
        self,
        run_id: str,
        run_dir: str | Path,
        metadata: dict[str, Any],
        warnings: list[str] | None = None,
    ) -> None:
        now = utc_now()
        warnings = warnings or []
        initial_stats = initial_stats_from_metadata(metadata, warnings)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO runs (
                    run_id, run_index, seed, status, stage, run_dir,
                    started_at, updated_at, duration_secs, warnings, metadata, stats
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    run_index=excluded.run_index,
                    seed=excluded.seed,
                    status=excluded.status,
                    stage=excluded.stage,
                    run_dir=excluded.run_dir,
                    updated_at=excluded.updated_at,
                    duration_secs=excluded.duration_secs,
                    warnings=excluded.warnings,
                    metadata=excluded.metadata,
                    stats=CASE
                        WHEN runs.stats = '{}' THEN excluded.stats
                        ELSE runs.stats
                    END
                """,
                (
                    run_id,
                    _metadata_run_index(metadata),
                    _metadata_seed(metadata),
                    "preparing",
                    "preparing",
                    str(Path(run_dir).resolve()),
                    now,
                    now,
                    _metadata_duration(metadata),
                    _json_dumps(warnings),
                    _json_dumps(metadata),
                    _json_dumps(initial_stats),
                ),
            )

    def update_stage(self, run_id: str, stage: str, status: str | None = None) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET stage = ?, status = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (stage, status or stage, now, run_id),
            )

    def update_progress(
        self,
        run_id: str,
        *,
        simulated_seconds: float,
        wall_seconds: float,
        duration_secs: float | None,
    ) -> None:
        duration = duration_secs or 0
        progress = simulated_seconds / duration if duration > 0 else 0.0
        progress = max(0.0, min(1.0, progress))
        current_slot = chain_slot_from_simulated_seconds(simulated_seconds)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET simulated_seconds = ?, wall_seconds = ?, current_slot = ?,
                    progress = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    round(simulated_seconds, 3),
                    round(wall_seconds, 3),
                    current_slot,
                    round(progress, 4),
                    utc_now(),
                    run_id,
                ),
            )

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        stats: dict[str, Any],
        warnings: list[str] | None = None,
    ) -> None:
        now = utc_now()
        warnings = warnings if warnings is not None else stats.get("warnings", [])
        with self._connect() as conn:
            row = conn.execute(
                "SELECT started_at, duration_secs FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            wall_seconds = 0.0
            duration_secs = None
            if row:
                duration_secs = row["duration_secs"]
                try:
                    start = datetime.fromisoformat(row["started_at"])
                    wall_seconds = max(0.0, (datetime.now(timezone.utc) - start).total_seconds())
                except ValueError:
                    wall_seconds = 0.0
            simulated_seconds = float(duration_secs or stats.get("fuzzer", {}).get("duration_secs") or 0)
            current_slot = chain_slot_from_simulated_seconds(simulated_seconds)
            conn.execute(
                """
                UPDATE runs
                SET status = ?, stage = ?, updated_at = ?, ended_at = ?,
                    warnings = ?, stats = ?, wall_seconds = ?,
                    simulated_seconds = CASE
                        WHEN simulated_seconds > ? THEN simulated_seconds
                        ELSE ?
                    END,
                    current_slot = CASE WHEN ? > 0 THEN ? ELSE current_slot END,
                    progress = CASE WHEN ? > 0 THEN 1 ELSE progress END
                WHERE run_id = ?
                """,
                (
                    status,
                    status,
                    now,
                    now,
                    _json_dumps(warnings or []),
                    _json_dumps(stats),
                    round(wall_seconds, 3),
                    simulated_seconds,
                    simulated_seconds,
                    simulated_seconds,
                    current_slot,
                    simulated_seconds,
                    run_id,
                ),
            )

    def update_stats_snapshot(
        self,
        run_id: str,
        stats: dict[str, Any],
        warnings: list[str] | None = None,
    ) -> None:
        with self._connect() as conn:
            existing = conn.execute(
                "SELECT warnings FROM runs WHERE run_id = ?",
                (run_id,),
            ).fetchone()
            if not existing:
                return
            merged_warnings = list(dict.fromkeys([
                *[
                    warning
                    for warning in _json_loads(existing["warnings"], [])
                    if not _is_transient_stats_warning(str(warning))
                ],
                *(warnings if warnings is not None else stats.get("warnings", [])),
            ]))
            conn.execute(
                """
                UPDATE runs
                SET stats = ?, warnings = ?, updated_at = ?
                WHERE run_id = ?
                """,
                (
                    _json_dumps(stats),
                    _json_dumps(merged_warnings),
                    utc_now(),
                    run_id,
                ),
            )

    def fail_run(self, run_id: str, error: str, warnings: list[str] | None = None) -> None:
        now = utc_now()
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET status = 'error', stage = 'error', updated_at = ?, ended_at = ?,
                    error = ?, warnings = ?
                WHERE run_id = ?
                """,
                (now, now, error, _json_dumps(warnings or []), run_id),
            )

    def insert_events(self, run_id: str, events: list[dict[str, Any]]) -> int:
        now = utc_now()
        inserted = 0
        with self._connect() as conn:
            for event in events:
                key = event.get("event_key") or event_key(run_id, event)
                before = conn.total_changes
                conn.execute(
                    """
                    INSERT OR IGNORE INTO events (
                        run_id, event_key, ts_ms, kind, host, slot, message, payload, created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        key,
                        float(event.get("ts_ms") or 0.0),
                        str(event["kind"]),
                        event.get("host"),
                        event.get("slot"),
                        str(event.get("message") or ""),
                        _json_dumps(event.get("payload", {})),
                        now,
                    ),
                )
                inserted += conn.total_changes - before
        return inserted

    def get_stats(self) -> dict[str, Any]:
        with self._connect() as conn:
            total = conn.execute("SELECT COUNT(*) FROM runs").fetchone()[0]
            if total == 0:
                return {
                    "total_runs": 0,
                    "success_runs": 0,
                    "warning_runs": 0,
                    "error_runs": 0,
                    "active_runs": 0,
                    "runs_per_minute": 0.0,
                    "recent_runs": [],
                }
            complete = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE status = 'complete'"
            ).fetchone()[0]
            warning = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE status = 'warning'"
            ).fetchone()[0]
            error = conn.execute(
                "SELECT COUNT(*) FROM runs WHERE status = 'error'"
            ).fetchone()[0]
            active = conn.execute(
                """
                SELECT COUNT(*) FROM runs
                WHERE status NOT IN ('complete', 'warning', 'error')
                """
            ).fetchone()[0]
            time_range = conn.execute(
                "SELECT MIN(started_at), MAX(updated_at) FROM runs"
            ).fetchone()
            runs_per_minute = 0.0
            if time_range[0] and time_range[1]:
                try:
                    start = datetime.fromisoformat(time_range[0])
                    end = datetime.fromisoformat(time_range[1])
                    minutes = (end - start).total_seconds() / 60
                    if minutes > 0:
                        runs_per_minute = total / minutes
                except ValueError:
                    runs_per_minute = 0.0
            recent_rows = conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT 20"
            ).fetchall()
            return {
                "total_runs": total,
                "success_runs": complete,
                "warning_runs": warning,
                "error_runs": error,
                "active_runs": active,
                "runs_per_minute": runs_per_minute,
                "recent_runs": [self._summary_from_row(r) for r in recent_rows],
            }

    def get_runs(self, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs ORDER BY id DESC LIMIT ? OFFSET ?",
                (limit, offset),
            ).fetchall()
            return [self._summary_from_row(row) for row in rows]

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM runs WHERE run_id = ?", (run_id,)).fetchone()
            return self._row_to_run(row) if row else None

    def get_progress(self, run_id: str) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if not run:
            return None
        return {
            "run_id": run["run_id"],
            "status": run["status"],
            "stage": run["stage"],
            "duration_secs": run["duration_secs"],
            "simulated_seconds": run["simulated_seconds"],
            "wall_seconds": run["wall_seconds"],
            "current_slot": run["current_slot"],
            "progress": run["progress"],
            "updated_at": run["updated_at"],
        }

    def get_events(
        self,
        run_id: str,
        *,
        kind: str | None = None,
        slot: int | None = None,
        host: str | None = None,
        limit: int = 100,
    ) -> list[dict[str, Any]]:
        query = "SELECT * FROM events WHERE run_id = ?"
        params: list[Any] = [run_id]
        if kind:
            query += " AND kind = ?"
            params.append(kind)
        if slot is not None:
            query += " AND slot = ?"
            params.append(slot)
        if host:
            query += " AND host = ?"
            params.append(host)
        query += " ORDER BY ts_ms DESC, id DESC LIMIT ?"
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_event(row) for row in rows]

    def _row_to_event(self, row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["id"],
            "run_id": row["run_id"],
            "ts_ms": row["ts_ms"],
            "kind": row["kind"],
            "host": row["host"],
            "slot": row["slot"],
            "message": row["message"],
            "payload": _json_loads(row["payload"], {}),
            "created_at": row["created_at"],
        }

    def get_max_event_id(self) -> int:
        with self._connect() as conn:
            return int(conn.execute("SELECT COALESCE(MAX(id), 0) FROM events").fetchone()[0])

    def get_events_since(self, event_id: int, limit: int = 500) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM events WHERE id > ? ORDER BY id ASC LIMIT ?",
                (event_id, limit),
            ).fetchall()
            return [self._row_to_event(row) for row in rows]

    def get_updated_runs_since(self, iso_timestamp: str) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM runs WHERE updated_at > ? ORDER BY updated_at ASC",
                (iso_timestamp,),
            ).fetchall()
            return [self._summary_from_row(row) for row in rows]

    def get_slots(self, run_id: str) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if not run:
            return None
        stats = run["stats"] or {}
        by_slot: dict[int, dict[str, Any]] = {}
        for block in stats.get("blocks", {}).get("slots", []):
            slot = int(block["slot"])
            by_slot.setdefault(slot, {"slot": slot})
            by_slot[slot].update(
                {
                    "proposer": block.get("proposer"),
                    "published_ms": block.get("published_ms"),
                    "n_received": block.get("n_received", 0),
                    "block_count": self._block_count_for_slot(run_id, slot),
                }
            )
        for coverage in stats.get("attestations", {}).get("coverage", {}).get("slots", []):
            slot = int(coverage["slot"])
            by_slot.setdefault(slot, {"slot": slot})
            by_slot[slot]["attestation_coverage"] = coverage.get(
                "n_nodes_reached_threshold", 0
            )
            by_slot[slot]["attestation_nodes"] = coverage.get("n_nodes", 0)
            if coverage.get("warning"):
                by_slot[slot]["warning"] = coverage["warning"]
        for slot in self._event_slots(run_id):
            by_slot.setdefault(slot, {"slot": slot})
            by_slot[slot]["block_count"] = self._block_count_for_slot(run_id, slot)
        return {"run_id": run_id, "slots": [by_slot[s] for s in sorted(by_slot)]}

    def _event_slots(self, run_id: str) -> list[int]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT slot FROM events
                WHERE run_id = ?
                  AND slot IS NOT NULL
                  AND kind IN (
                    'block_published',
                    'block_received',
                    'attestation_sent',
                    'attestation_received',
                    'aggregation_received',
                    'justified',
                    'finalized',
                    'chain_status'
                  )
                ORDER BY slot ASC
                """,
                (run_id,),
            ).fetchall()
        return [int(row["slot"]) for row in rows]

    def _block_count_for_slot(self, run_id: str, slot: int) -> int:
        return len(self._block_keys_for_slot(run_id, slot))

    def _block_keys_for_slot(self, run_id: str, slot: int) -> dict[str, dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE run_id = ?
                  AND slot = ?
                  AND kind IN ('block_published', 'block_received')
                ORDER BY ts_ms ASC
                """,
                (run_id, slot),
            ).fetchall()

        events = [self._row_to_event(row) for row in rows]
        hashes = sorted(
            {
                str(event["payload"].get("block_hash"))
                for event in events
                if event["payload"].get("block_hash")
            }
        )
        proposers = sorted(
            {
                int(event["payload"].get("proposer"))
                for event in events
                if event["payload"].get("proposer") is not None
            }
        )

        def _event_block_key(event: dict[str, Any]) -> str:
            payload = event["payload"]
            block_hash = payload.get("block_hash")
            proposer = payload.get("proposer")
            if len(hashes) == 1 and len(proposers) <= 1:
                return f"hash:{hashes[0]}"
            if len(hashes) == 0 and len(proposers) <= 1:
                return f"proposer:{proposers[0]}" if proposers else f"slot:{slot}"
            if block_hash:
                return f"hash:{block_hash}"
            if proposer is not None:
                return f"proposer:{proposer}"
            return f"slot:{slot}"

        blocks: dict[str, dict[str, Any]] = {}
        for event in events:
            payload = event["payload"]
            block_hash = payload.get("block_hash")
            proposer = payload.get("proposer")
            key = _event_block_key(event)
            blocks.setdefault(
                key,
                {
                    "block_id": key,
                    "block_hash": block_hash
                    or (hashes[0] if len(hashes) == 1 else None),
                    "proposer": proposer
                    if proposer is not None
                    else (proposers[0] if len(proposers) == 1 else None),
                    "hosts": set(),
                    "events": 0,
                },
            )
            if block_hash and not blocks[key].get("block_hash"):
                blocks[key]["block_hash"] = block_hash
            if proposer is not None and blocks[key].get("proposer") is None:
                blocks[key]["proposer"] = proposer
            if event.get("host"):
                blocks[key]["hosts"].add(event["host"])
            blocks[key]["events"] += 1
        for block in blocks.values():
            block["hosts"] = sorted(block["hosts"])
            block["host_count"] = len(block["hosts"])
        return blocks

    def get_slot_detail(self, run_id: str, slot: int) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if not run:
            return None
        stats = run["stats"] or {}
        blocks = self._block_keys_for_slot(run_id, slot)
        if len(blocks) > 1:
            return {
                "run_id": run_id,
                "slot": slot,
                "state": "conflict",
                "error": "Multiple blocks were observed for this slot; CDF is hidden.",
                "blocks": list(blocks.values()),
            }

        block_slot = None
        for item in stats.get("blocks", {}).get("slots", []):
            if int(item.get("slot", -1)) == slot:
                block_slot = item
                break
        if block_slot is None and len(blocks) == 1:
            block_slot = self._live_block_slot_from_events(run_id, slot)

        coverage_slot = None
        for item in stats.get("attestations", {}).get("coverage", {}).get("slots", []):
            if int(item.get("slot", -1)) == slot:
                coverage_slot = item
                break

        if not block_slot:
            return {
                "run_id": run_id,
                "slot": slot,
                "state": "no_data",
                "error": "No block propagation data was found for this slot.",
                "blocks": list(blocks.values()),
            }

        times = sorted(float(v) for v in block_slot.get("receive_timestamps_ms", {}).values())
        first = times[0] if times else 0.0
        cdf = [
            {
                "latency_ms": round(ts - first, 1),
                "received": index + 1,
                "percent": round(((index + 1) / len(times)) * 100, 1),
            }
            for index, ts in enumerate(times)
        ]
        slot_stats = {
            "proposer": block_slot.get("proposer"),
            "published_ms": block_slot.get("published_ms"),
            "first_receive_ms": block_slot.get("first_receive_ms"),
            "last_receive_ms": block_slot.get("last_receive_ms"),
            "n_received": block_slot.get("n_received", 0),
            "nodes": run["metadata"].get("simulation", {}).get("total_nodes", 0),
            "cdf_p50_ms": _percentile([p["latency_ms"] for p in cdf], 0.50),
            "cdf_p95_ms": _percentile([p["latency_ms"] for p in cdf], 0.95),
            "attestation_coverage": coverage_slot,
        }
        return {
            "run_id": run_id,
            "slot": slot,
            "state": "ok",
            "block_count": len(blocks) or 1,
            "block": next(iter(blocks.values()), None),
            "cdf": cdf,
            "slot_stats": slot_stats,
        }

    def _live_block_slot_from_events(self, run_id: str, slot: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM events
                WHERE run_id = ?
                  AND slot = ?
                  AND kind IN ('block_published', 'block_received')
                ORDER BY ts_ms ASC
                """,
                (run_id, slot),
            ).fetchall()
        if not rows:
            return None

        receive_times: dict[str, float] = {}
        published_ms: float | None = None
        proposer = None
        block_hash = ""
        for row in rows:
            event = self._row_to_event(row)
            payload = event["payload"]
            proposer = payload.get("proposer", proposer)
            block_hash = payload.get("block_hash", block_hash)
            if event["kind"] == "block_published":
                if published_ms is None or event["ts_ms"] < published_ms:
                    published_ms = float(event["ts_ms"])
            elif event["kind"] == "block_received" and event.get("host"):
                host = event["host"]
                ts_ms = float(event["ts_ms"])
                if host not in receive_times or ts_ms < receive_times[host]:
                    receive_times[host] = ts_ms

        if not receive_times:
            return None
        times = sorted(receive_times.values())
        block_slot: dict[str, Any] = {
            "slot": slot,
            "proposer": proposer,
            "block_hash": block_hash,
            "first_receive_ms": times[0],
            "last_receive_ms": times[-1],
            "n_received": len(times),
            "receive_timestamps_ms": receive_times,
        }
        if published_ms is not None:
            block_slot["published_ms"] = published_ms
        return block_slot

    def get_chain(self, run_id: str, slot: int | None = None) -> dict[str, Any] | None:
        run = self.get_run(run_id)
        if not run:
            return None
        latest: dict[str, dict[str, Any]] = {}
        slots: list[int] = []
        for slot_entry in run["stats"].get("chain_status", {}).get("slots", []):
            chain_slot = int(slot_entry.get("slot", 0))
            slots.append(chain_slot)
            if slot is not None and chain_slot > slot:
                continue
            for host, status in slot_entry.get("hosts", {}).items():
                previous = latest.get(host)
                if previous is None or chain_slot >= previous["reported_slot"]:
                    latest[host] = {
                        "peer": host,
                        "reported_slot": chain_slot,
                        "head_slot": status.get("head_slot"),
                        "head_root": status.get("head_root"),
                        "justified_slot": status.get("latest_justified_slot"),
                        "justified_root": status.get("latest_justified_root"),
                        "finalized_slot": status.get("latest_finalized_slot"),
                        "finalized_root": status.get("latest_finalized_root"),
                        "ts_ms": status.get("ts_ms"),
                        "source": status.get("source"),
                    }
        unique_slots = sorted(set(slots))
        selected_slot = slot
        if selected_slot is None and unique_slots:
            selected_slot = unique_slots[-1]
        return {
            "run_id": run_id,
            "selected_slot": selected_slot,
            "slots": unique_slots,
            "peers": [latest[k] for k in sorted(latest)],
        }

    def index_run_dir(self, run_dir: str | Path, *, overwrite: bool = False) -> bool:
        run_path = Path(run_dir)
        metadata_path = run_path / "run-metadata.json"
        stats_path = run_path / "stats.json"
        if not metadata_path.is_file() and not stats_path.is_file():
            return False
        metadata = _load_json(metadata_path)
        stats = _load_json(stats_path)
        run_id = str(metadata.get("run_id") or stats.get("run_id") or run_path.name)
        existing = self.get_run(run_id)
        if existing and not overwrite:
            if stats and not existing.get("stats"):
                status = _status_from_stats(stats)
                warnings = stats.get("warnings", [])
                self.finish_run(
                    run_id,
                    status=status,
                    stats=stats,
                    warnings=warnings,
                )
                if status == "error" and stats.get("error"):
                    self.fail_run(run_id, str(stats["error"]), warnings)
            return False

        if not metadata:
            metadata = {
                "run_id": run_id,
                "run_index": stats.get("run_index"),
                "fuzzer": stats.get("fuzzer", {}),
                "simulation": stats.get("simulation", {}),
                "clients": stats.get("clients", {}),
                "node_counts": stats.get("node_counts", {}),
            }
        self.start_run(run_id, run_path, metadata, stats.get("warnings", []))
        if stats:
            status = _status_from_stats(stats)
            warnings = stats.get("warnings", [])
            self.finish_run(
                run_id,
                status=status,
                stats=stats,
                warnings=warnings,
            )
            if status == "error" and stats.get("error"):
                self.fail_run(run_id, str(stats["error"]), warnings)
        self.insert_events(run_id, events_from_run(run_path))
        return True

    def reindex_output_dir(self, output_dir: str | Path) -> int:
        output_path = Path(output_dir)
        if not output_path.is_dir():
            return 0
        indexed = 0
        for run_dir in sorted(output_path.iterdir()):
            if run_dir.is_dir() and self.index_run_dir(run_dir):
                indexed += 1
        return indexed


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return {}


def _status_from_stats(stats: dict[str, Any]) -> str:
    status = stats.get("status")
    if status in {"complete", "warning", "error"}:
        return str(status)
    return "warning" if stats.get("warnings") else "complete"


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    idx = min(len(ordered) - 1, max(0, math.ceil(percentile * len(ordered)) - 1))
    return round(ordered[idx], 1)
