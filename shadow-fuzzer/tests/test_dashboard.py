from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FUZZER_ROOT))

from dashboard_db import DashboardDB
from dashboard_events import events_from_run
from dashboard_server import create_app


def _metadata(run_id: str = "silver-quiet-lotus") -> dict:
    return {
        "run_id": run_id,
        "run_index": 6,
        "fuzzer": {
            "run_index": 6,
            "seed": 48,
            "duration_secs": 120,
            "runner": "docker-arm",
        },
        "simulation": {
            "total_nodes": 9,
            "total_subnets": 1,
            "aggregators_per_subnet": 2,
        },
        "clients": {"qlean": 0.6, "zeam": 0.4},
        "node_counts": {"qlean": 5, "zeam": 4},
    }


def _stats(run_id: str = "silver-quiet-lotus") -> dict:
    metadata = _metadata(run_id)
    return {
        **metadata,
        "warnings": [],
        "node_distribution": {
            "clients": metadata["node_counts"],
            "regions": {"europe": 3, "us-east": 3, "asia": 2},
            "bandwidths": {"50 Mbit": 7, "1 Gbit": 2},
        },
        "blocks": {
            "summary": {"n_published": 1, "n_received": 1},
            "slots": [
                {
                    "slot": 8,
                    "proposer": 4,
                    "published_ms": 32020.0,
                    "first_receive_ms": 32110.0,
                    "last_receive_ms": 32931.0,
                    "n_received": 3,
                    "receive_timestamps_ms": {
                        "qlean_0": 32110.0,
                        "qlean_1": 32470.0,
                        "zeam_0": 32931.0,
                    },
                }
            ],
        },
        "chain_status": {
            "summary": {"slots_with_data": 1, "hosts_with_data": 2},
            "slots": [
                {
                    "slot": 12,
                    "hosts": {
                        "qlean_0": {
                            "head_slot": 12,
                            "head_root": "abc",
                            "latest_justified_slot": 8,
                            "latest_justified_root": "def",
                            "latest_finalized_slot": 8,
                            "latest_finalized_root": "fed",
                            "ts_ms": 48000.0,
                        },
                        "zeam_0": {
                            "head_slot": 11,
                            "head_root": "aaa",
                            "latest_justified_slot": 8,
                            "latest_justified_root": "bbb",
                            "latest_finalized_slot": 8,
                            "latest_finalized_root": "ccc",
                            "ts_ms": 48100.0,
                        },
                    },
                }
            ],
        },
        "attestations": {
            "slots": [],
            "summary": {},
            "coverage": {
                "slots": [
                    {
                        "slot": 8,
                        "n_nodes_reached_threshold": 8,
                        "n_nodes": 9,
                        "p95_nodes_to_95_attestations_ms": 744.0,
                    }
                ],
                "summary": {"slots_with_data": 1},
            },
        },
        "event_counts": {},
    }


class DashboardDBTests(unittest.TestCase):
    def test_run_lifecycle_and_slot_detail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = DashboardDB(root / "runs.db")
            metadata = _metadata()
            db.start_run("silver-quiet-lotus", root / "silver-quiet-lotus", metadata)
            db.update_stage("silver-quiet-lotus", "running_shadow")
            db.update_progress(
                "silver-quiet-lotus",
                simulated_seconds=82.0,
                wall_seconds=108.0,
                duration_secs=120.0,
            )
            db.finish_run("silver-quiet-lotus", status="complete", stats=_stats())

            run = db.get_run("silver-quiet-lotus")
            self.assertIsNotNone(run)
            self.assertEqual(run["status"], "complete")
            self.assertEqual(db.get_progress("silver-quiet-lotus")["current_slot"], 30)

            detail = db.get_slot_detail("silver-quiet-lotus", 8)
            self.assertEqual(detail["state"], "ok")
            self.assertEqual(detail["slot_stats"]["n_received"], 3)
            self.assertEqual(detail["cdf"][-1]["percent"], 100.0)

    def test_reindex_existing_output_dir(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "silver-quiet-lotus"
            run_dir.mkdir()
            (run_dir / "run-metadata.json").write_text(json.dumps(_metadata()))
            (run_dir / "stats.json").write_text(json.dumps(_stats()))

            db = DashboardDB(root / "runs.db")
            self.assertEqual(db.reindex_output_dir(root), 1)
            self.assertEqual(db.get_stats()["total_runs"], 1)
            self.assertEqual(db.get_chain("silver-quiet-lotus")["peers"][0]["peer"], "qlean_0")

    def test_slot_conflict_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = DashboardDB(root / "runs.db")
            db.start_run("conflict-run", root / "conflict-run", _metadata("conflict-run"))
            db.finish_run("conflict-run", status="complete", stats=_stats("conflict-run"))
            db.insert_events(
                "conflict-run",
                [
                    {
                        "kind": "block_published",
                        "host": "qlean_0",
                        "slot": 8,
                        "ts_ms": 1000,
                        "message": "qlean_0 published block",
                        "payload": {"block_hash": "aaaa", "proposer": 1},
                    },
                    {
                        "kind": "block_received",
                        "host": "zeam_0",
                        "slot": 8,
                        "ts_ms": 1100,
                        "message": "zeam_0 received block",
                        "payload": {"block_hash": "bbbb", "proposer": 2},
                    },
                ],
            )
            detail = db.get_slot_detail("conflict-run", 8)
            self.assertEqual(detail["state"], "conflict")
            self.assertEqual(len(detail["blocks"]), 2)


class DashboardEventTests(unittest.TestCase):
    def test_event_parser_mappings_and_chain_deltas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            host_dir = run_dir / "shadow.data" / "hosts" / "qlean_0"
            host_dir.mkdir(parents=True)
            (host_dir / "qlean.stdout").write_text(
                "\n".join(
                    [
                        '["LEAN-INTEROP-TEST", 946684864000, "PUBLISH-ATTESTATION", [1, [0, 0, 0, 1, "abc"]]]',
                        '["LEAN-INTEROP-TEST", 946684865000, "RECEIVE-ATTESTATION", [2, [0, 0, 0, 1, "abc"]]]',
                        '["LEAN-INTEROP-TEST", 946684866000, "PUBLISH-BLOCK", {"slot": 2, "hash": "abcd", "proposer": 4}]',
                        "1.1.1 00:01:07.000000 CHAIN STATUS Current Slot: 3 Head Slot: 3",
                        "Head Block Root: 0xbeef",
                        "Latest Justified: Slot 2 | Root: 0xcafe",
                        "Latest Finalized: Slot 1 | Root: 0xfade",
                    ]
                )
            )

            kinds = {event["kind"] for event in events_from_run(run_dir)}
            self.assertIn("attestation_sent", kinds)
            self.assertIn("attestation_received", kinds)
            self.assertIn("block_published", kinds)
            self.assertIn("chain_status", kinds)
            self.assertIn("justified", kinds)
            self.assertIn("finalized", kinds)


class DashboardAPITests(unittest.TestCase):
    def test_api_detail_filters_and_downloads(self) -> None:
        from fastapi.testclient import TestClient

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "silver-quiet-lotus"
            host_dir = run_dir / "shadow.data" / "hosts" / "qlean_0"
            host_dir.mkdir(parents=True)
            (run_dir / "shadow.yaml").write_text("general:\n  stop_time: 120s\n")
            (host_dir / "qlean.stdout").write_text("hello\n")

            db = DashboardDB(root / "runs.db")
            db.start_run("silver-quiet-lotus", run_dir, _metadata())
            db.finish_run("silver-quiet-lotus", status="complete", stats=_stats())
            db.insert_events(
                "silver-quiet-lotus",
                [
                    {
                        "kind": "block_received",
                        "host": "qlean_0",
                        "slot": 8,
                        "ts_ms": 1000,
                        "message": "qlean_0 received block",
                        "payload": {"block_hash": "abcd", "proposer": 4},
                    }
                ],
            )

            app = create_app(root, static_dir=root / "missing-dist")
            with TestClient(app) as client:
                self.assertEqual(client.get("/api/stats").json()["total_runs"], 1)
                self.assertEqual(
                    client.get("/api/run/silver-quiet-lotus").json()["run_id"],
                    "silver-quiet-lotus",
                )
                events = client.get(
                    "/api/run/silver-quiet-lotus/events?kind=block_received"
                ).json()
                self.assertEqual(len(events), 1)
                self.assertEqual(
                    client.get("/api/run/silver-quiet-lotus/shadow.yaml").status_code,
                    200,
                )
                self.assertEqual(
                    client.get("/api/run/silver-quiet-lotus/logs.zip").status_code,
                    200,
                )
                self.assertEqual(
                    client.get("/api/run/silver-quiet-lotus/node/qlean_0/logs.zip").status_code,
                    200,
                )
                self.assertEqual(
                    client.get("/api/run/silver-quiet-lotus/node/missing/logs.zip").status_code,
                    404,
                )


if __name__ == "__main__":
    unittest.main()
