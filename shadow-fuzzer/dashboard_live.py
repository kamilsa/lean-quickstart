"""Live polling helpers for the Shadow fuzzer dashboard."""

from __future__ import annotations

import threading
import time
from pathlib import Path

from dashboard_db import DashboardDB
from dashboard_events import events_from_run, max_simulated_seconds_from_run, stats_from_run


class RunLogWatcher:
    """Poll Shadow host logs while a run is active.

    The parser intentionally reparses the run directory each tick and relies on
    SQLite's event keys to deduplicate. Fuzzer runs are small enough for this to
    be simpler and more robust than maintaining file offsets across Shadow's
    output layout.
    """

    def __init__(
        self,
        db: DashboardDB,
        run_id: str,
        run_dir: str | Path,
        duration_secs: float | None,
        *,
        poll_interval: float = 1.0,
    ) -> None:
        self.db = db
        self.run_id = run_id
        self.run_dir = Path(run_dir)
        self.duration_secs = duration_secs
        self.poll_interval = poll_interval
        self.started = time.monotonic()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def stop_and_join(self) -> None:
        self.stop()
        self.join(timeout=max(2.0, self.poll_interval * 2))
        self.snapshot()

    def snapshot(self) -> None:
        wall_elapsed = time.monotonic() - self.started
        try:
            events = events_from_run(self.run_dir)
            self.db.insert_events(self.run_id, events)
            simulated = max_simulated_seconds_from_run(self.run_dir)
            run = self.db.get_run(self.run_id)
            if run:
                stats = stats_from_run(self.run_dir, run.get("metadata", {}))
                self.db.update_stats_snapshot(
                    self.run_id,
                    stats,
                    warnings=stats.get("warnings", []),
                )
        except FileNotFoundError:
            simulated = 0.0
        except Exception as exc:
            self.db.insert_events(
                self.run_id,
                [
                    {
                        "kind": "warning",
                        "host": None,
                        "slot": None,
                        "ts_ms": wall_elapsed * 1000,
                        "message": f"Dashboard log watcher could not parse logs: {exc}",
                        "payload": {"source": "dashboard_watcher"},
                    }
                ],
            )
            simulated = 0.0

        if simulated <= 0:
            simulated = wall_elapsed
        if self.duration_secs:
            simulated = min(float(self.duration_secs), simulated)
        self.db.update_progress(
            self.run_id,
            simulated_seconds=simulated,
            wall_seconds=wall_elapsed,
            duration_secs=self.duration_secs,
        )

    def _run(self) -> None:
        while not self._stop.wait(self.poll_interval):
            self.snapshot()
