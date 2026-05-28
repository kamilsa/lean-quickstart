from __future__ import annotations

import contextlib
import io
import json
import importlib.util
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

FUZZER_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(FUZZER_ROOT))

from dashboard_db import DashboardDB
from dashboard_events import events_from_run
from dashboard_server import create_app
from dashboard_time import chain_slot_from_simulated_seconds, max_chain_slot_for_duration

FUZZER_SCRIPT = FUZZER_ROOT / "shadow-fuzzer.py"
_FUZZER_SPEC = importlib.util.spec_from_file_location("shadow_fuzzer_script", FUZZER_SCRIPT)
assert _FUZZER_SPEC and _FUZZER_SPEC.loader
shadow_fuzzer_script = importlib.util.module_from_spec(_FUZZER_SPEC)
_FUZZER_SPEC.loader.exec_module(shadow_fuzzer_script)


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
            self.assertEqual(db.get_progress("silver-quiet-lotus")["current_slot"], 5)
            db.finish_run("silver-quiet-lotus", status="complete", stats=_stats())

            run = db.get_run("silver-quiet-lotus")
            self.assertIsNotNone(run)
            self.assertEqual(run["status"], "complete")
            self.assertEqual(db.get_progress("silver-quiet-lotus")["current_slot"], 15)

            detail = db.get_slot_detail("silver-quiet-lotus", 8)
            self.assertEqual(detail["state"], "ok")
            self.assertEqual(detail["slot_stats"]["n_received"], 3)
            self.assertEqual(detail["cdf"][-1]["percent"], 100.0)

    def test_slot_helpers_account_for_genesis_delay(self) -> None:
        self.assertEqual(chain_slot_from_simulated_seconds(0), 0)
        self.assertEqual(chain_slot_from_simulated_seconds(59.9), 0)
        self.assertEqual(chain_slot_from_simulated_seconds(60), 0)
        self.assertEqual(chain_slot_from_simulated_seconds(64), 1)
        self.assertEqual(chain_slot_from_simulated_seconds(82), 5)
        self.assertEqual(max_chain_slot_for_duration(120), 15)

    def test_initial_and_live_data_before_stats_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = DashboardDB(root / "runs.db")
            db.start_run("live-run", root / "live-run", _metadata("live-run"))

            run = db.get_run("live-run")
            self.assertEqual(run["stats"]["node_distribution"]["clients"]["qlean"], 5)

            db.insert_events(
                "live-run",
                [
                    {
                        "kind": "block_published",
                        "host": "qlean_0",
                        "slot": 4,
                        "ts_ms": 76000,
                        "message": "qlean_0 published block",
                        "payload": {"block_hash": "aaaa", "proposer": 1},
                    },
                    {
                        "kind": "block_received",
                        "host": "qlean_1",
                        "slot": 4,
                        "ts_ms": 76100,
                        "message": "qlean_1 received block",
                        "payload": {"block_hash": "aaaa", "proposer": 1},
                    },
                    {
                        "kind": "block_received",
                        "host": "zeam_0",
                        "slot": 4,
                        "ts_ms": 76400,
                        "message": "zeam_0 received block",
                        "payload": {"block_hash": "aaaa", "proposer": 1},
                    },
                ],
            )

            slots = db.get_slots("live-run")["slots"]
            self.assertEqual(slots[0]["slot"], 4)
            detail = db.get_slot_detail("live-run", 4)
            self.assertEqual(detail["state"], "ok")
            self.assertEqual(detail["slot_stats"]["n_received"], 2)
            self.assertEqual(detail["cdf"][-1]["latency_ms"], 300.0)

    def test_stats_snapshot_clears_transient_parser_warnings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = DashboardDB(root / "runs.db")
            db.start_run(
                "live-run",
                root / "live-run",
                _metadata("live-run"),
                ["total_subnets (2) > total_nodes (1)"],
            )
            db.update_stats_snapshot(
                "live-run",
                {
                    **_stats("live-run"),
                    "warnings": [
                        "shadow.data/hosts directory not found; no propagation stats available",
                        "No propagation events found in any host stdout/stderr",
                    ],
                },
            )
            db.update_stats_snapshot("live-run", {**_stats("live-run"), "warnings": []})

            self.assertEqual(
                db.get_run("live-run")["warnings"],
                ["total_subnets (2) > total_nodes (1)"],
            )

    def test_hash_sig_key_cache_helpers_use_validator_count_and_active_epoch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            genesis = root / "run" / "genesis"
            keys = genesis / "hash-sig-keys"
            keys.mkdir(parents=True)
            (genesis / "validator-config.yaml").write_text(
                """
config:
  activeEpoch: 18
validators:
  - name: qlean_0
    count: 1
  - name: zeam_0
    count: 2
"""
            )
            (keys / "validator-keys-manifest.yaml").write_text("validators: []\n")
            (keys / "validator_0_pk.ssz").write_text("pk")

            cache_root = root / "cache"
            cache_dir = cache_root / "validators-3-active-18"
            self.assertEqual(shadow_fuzzer_script._hash_sig_cache_key(genesis), "validators-3-active-18")
            with contextlib.redirect_stdout(io.StringIO()):
                shadow_fuzzer_script._store_hash_sig_key_cache(genesis, cache_dir)
            self.assertTrue((cache_dir / "validator_0_pk.ssz").is_file())

            shutil.rmtree(keys)
            with contextlib.redirect_stdout(io.StringIO()):
                restored = shadow_fuzzer_script._restore_hash_sig_key_cache(genesis, cache_root)
            self.assertEqual(restored, cache_dir)
            self.assertTrue((keys / "validator_0_pk.ssz").is_file())

    def test_clean_dashboard_db_removes_sqlite_files_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename in ("runs.db", "runs.db-shm", "runs.db-wal"):
                (root / filename).write_text("db")
            keep = root / "some-run"
            keep.mkdir()

            removed = shadow_fuzzer_script._clean_dashboard_db(root)
            self.assertEqual({path.name for path in removed}, {"runs.db", "runs.db-shm", "runs.db-wal"})
            self.assertFalse((root / "runs.db").exists())
            self.assertTrue(keep.is_dir())

    def test_clean_output_dir_preserves_hash_sig_key_cache(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for filename in ("runs.db", "runs.db-shm", "runs.db-wal"):
                (root / filename).write_text("db")
            run_dir = root / "silver-quiet-lotus"
            run_dir.mkdir()
            (run_dir / "run-metadata.json").write_text("{}")
            build_dir = root / "_docker-build"
            build_dir.mkdir()
            (build_dir / "Dockerfile").write_text("FROM scratch\n")
            cache_dir = root / shadow_fuzzer_script.HASH_SIG_KEY_CACHE_DIR
            cache_dir.mkdir()
            (cache_dir / "validator_0_pk.ssz").write_text("pk")

            removed = shadow_fuzzer_script._clean_output_dir(root)
            self.assertEqual(
                {path.name for path in removed},
                {"runs.db", "runs.db-shm", "runs.db-wal", "silver-quiet-lotus", "_docker-build"},
            )
            self.assertEqual([path.name for path in root.iterdir()], [shadow_fuzzer_script.HASH_SIG_KEY_CACHE_DIR])
            self.assertTrue((cache_dir / "validator_0_pk.ssz").is_file())

    def test_failed_shadow_stats_snapshot_records_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            error = "Shadow exited with status 1"
            with contextlib.redirect_stdout(io.StringIO()):
                stats = shadow_fuzzer_script._write_stats_snapshot(
                    run_dir,
                    _metadata("failed-shadow-run"),
                    [error],
                    status="error",
                    error=error,
                )

            written = json.loads((run_dir / "stats.json").read_text())
            self.assertEqual(stats["status"], "error")
            self.assertEqual(written["error"], error)
            self.assertIn(error, written["warnings"])

    def test_shadow_failure_message_includes_returncode(self) -> None:
        exc = subprocess.CalledProcessError(7, ["shadow", "-d", "out", "shadow.yaml"])
        self.assertIn("status 7", shadow_fuzzer_script._shadow_failure_message(exc))

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

    def test_chain_view_can_select_historical_slot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stats = _stats()
            stats["chain_status"]["slots"].append({
                "slot": 14,
                "hosts": {
                    "qlean_0": {
                        "head_slot": 14,
                        "head_root": "new",
                        "latest_justified_slot": 12,
                        "latest_justified_root": "new-justified",
                        "latest_finalized_slot": 11,
                        "latest_finalized_root": "new-finalized",
                        "ts_ms": 56000.0,
                    },
                    "zeam_0": {
                        "head_slot": 14,
                        "head_root": "zeam-new",
                        "latest_justified_slot": 12,
                        "latest_justified_root": "zeam-justified",
                        "latest_finalized_slot": 11,
                        "latest_finalized_root": "zeam-finalized",
                        "ts_ms": 56100.0,
                    },
                },
            })
            run_dir = root / "silver-quiet-lotus"
            db = DashboardDB(root / "runs.db")
            db.start_run("silver-quiet-lotus", run_dir, _metadata())
            db.finish_run("silver-quiet-lotus", status="complete", stats=stats)

            historical = db.get_chain("silver-quiet-lotus", slot=12)
            latest = db.get_chain("silver-quiet-lotus")

            self.assertEqual(historical["selected_slot"], 12)
            self.assertEqual(historical["slots"], [12, 14])
            self.assertEqual(historical["peers"][0]["head_slot"], 12)
            self.assertEqual(latest["selected_slot"], 14)
            self.assertEqual(latest["peers"][0]["head_slot"], 14)
            self.assertEqual(latest["peers"][0]["justified_slot"], 12)

    def test_reindex_preserves_error_status_from_stats(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            run_dir = root / "failed-shadow-run"
            run_dir.mkdir()
            stats = _stats("failed-shadow-run")
            stats["status"] = "error"
            stats["error"] = "Shadow exited with status 1"
            stats["warnings"] = [stats["error"]]
            (run_dir / "run-metadata.json").write_text(json.dumps(_metadata("failed-shadow-run")))
            (run_dir / "stats.json").write_text(json.dumps(stats))

            db = DashboardDB(root / "runs.db")
            self.assertEqual(db.reindex_output_dir(root), 1)
            run = db.get_run("failed-shadow-run")
            self.assertEqual(run["status"], "error")
            self.assertEqual(run["error"], stats["error"])

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

    def test_mixed_block_hash_and_proposer_events_do_not_create_false_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            db = DashboardDB(root / "runs.db")
            db.start_run(
                "mixed-block-run",
                root / "mixed-block-run",
                _metadata("mixed-block-run"),
            )
            db.insert_events(
                "mixed-block-run",
                [
                    {
                        "kind": "block_received",
                        "host": "qlean_0",
                        "slot": 3,
                        "ts_ms": 72000,
                        "message": "qlean_0 received block",
                        "payload": {"block_hash": "f117450cc2dd"},
                    },
                    {
                        "kind": "block_received",
                        "host": "zeam_0",
                        "slot": 3,
                        "ts_ms": 72125,
                        "message": "zeam_0 received block",
                        "payload": {"proposer": 1},
                    },
                ],
            )

            detail = db.get_slot_detail("mixed-block-run", 3)
            self.assertEqual(detail["state"], "ok")
            self.assertEqual(detail["block_count"], 1)
            self.assertEqual(detail["slot_stats"]["n_received"], 2)


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
