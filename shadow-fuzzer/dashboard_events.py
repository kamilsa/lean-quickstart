"""Dashboard event extraction helpers for Shadow fuzzer runs.

This module wraps the existing stats-shadow.py parser and normalizes its
internal event names into the public dashboard event taxonomy.
"""

from __future__ import annotations

import hashlib
import importlib.util
import contextlib
import io
import json
import re
from pathlib import Path
from typing import Any

FUZZER_ROOT = Path(__file__).resolve().parent
STATS_SHADOW_PATH = FUZZER_ROOT / "stats-shadow.py"


def _load_stats_shadow() -> Any:
    spec = importlib.util.spec_from_file_location("stats_shadow", STATS_SHADOW_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"failed to load {STATS_SHADOW_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_STATS_SHADOW = _load_stats_shadow()


KIND_MAP = {
    "publish_attestation": "attestation_sent",
    "receive_attestation": "attestation_received",
    "publish_block": "block_published",
    "receive_block": "block_received",
    "chain_status": "chain_status",
}


def _hosts_dir_for_run(run_dir: Path) -> Path | None:
    candidates = [
        run_dir / "shadow.data" / "hosts",
        run_dir / "hosts",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def event_ts_ms(event: dict[str, Any]) -> float:
    return float(_STATS_SHADOW._event_ts_ms(event))


def event_key(run_id: str, event: dict[str, Any]) -> str:
    payload = {
        "run_id": run_id,
        "kind": event.get("kind"),
        "host": event.get("host"),
        "slot": event.get("slot"),
        "ts_ms": round(float(event.get("ts_ms", 0.0)), 3),
        "message": event.get("message"),
        "payload": event.get("payload", {}),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha1(encoded).hexdigest()


def _block_label(event: dict[str, Any]) -> str:
    block_hash = str(event.get("block_hash") or "")
    if block_hash:
        return f"0x{block_hash[:10]}"
    proposer = event.get("proposer")
    if proposer is not None:
        return f"proposer {proposer}"
    return "block"


def _event_message(kind: str, host: str, event: dict[str, Any]) -> str:
    slot = event.get("slot")
    if kind == "attestation_sent":
        validator = event.get("validator_id")
        suffix = f" by validator {validator}" if validator is not None else ""
        return f"{host} sent attestation for slot {slot}{suffix}."
    if kind == "attestation_received":
        validator = event.get("validator_id")
        suffix = f" from validator {validator}" if validator is not None else ""
        return f"{host} received attestation for slot {slot}{suffix}."
    if kind == "block_published":
        return f"{host} published {_block_label(event)} at slot {slot}."
    if kind == "block_received":
        return f"{host} received {_block_label(event)} at slot {slot}."
    if kind == "chain_status":
        return (
            f"{host} reported head {event.get('head_slot')}, "
            f"justified {event.get('latest_justified_slot')}, "
            f"finalized {event.get('latest_finalized_slot')}."
        )
    return f"{host} emitted {kind}."


def _normalize_event(raw_kind: str, host: str, event: dict[str, Any]) -> dict[str, Any]:
    kind = KIND_MAP[raw_kind]
    slot = event.get("slot")
    if slot is None and raw_kind == "chain_status":
        slot = event.get("head_slot")
    payload = dict(event)
    payload.pop("host", None)
    return {
        "kind": kind,
        "host": host,
        "slot": int(slot) if slot is not None else None,
        "ts_ms": round(event_ts_ms(event), 3),
        "message": _event_message(kind, host, event),
        "payload": payload,
    }


def _derive_chain_delta_events(host: str, events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    derived: list[dict[str, Any]] = []
    previous_justified = -1
    previous_finalized = -1

    for event in sorted(events, key=event_ts_ms):
        ts_ms = round(event_ts_ms(event), 3)
        justified = int(event.get("latest_justified_slot", -1))
        finalized = int(event.get("latest_finalized_slot", -1))

        if justified > previous_justified:
            derived.append(
                {
                    "kind": "justified",
                    "host": host,
                    "slot": justified,
                    "ts_ms": ts_ms,
                    "message": f"{host} advanced justified checkpoint to slot {justified}.",
                    "payload": {
                        "source_chain_slot": event.get("slot"),
                        "root": event.get("latest_justified_root"),
                        "head_slot": event.get("head_slot"),
                    },
                }
            )
            previous_justified = justified

        if finalized > previous_finalized:
            derived.append(
                {
                    "kind": "finalized",
                    "host": host,
                    "slot": finalized,
                    "ts_ms": ts_ms,
                    "message": f"{host} advanced finalized checkpoint to slot {finalized}.",
                    "payload": {
                        "source_chain_slot": event.get("slot"),
                        "root": event.get("latest_finalized_root"),
                        "head_slot": event.get("head_slot"),
                    },
                }
            )
            previous_finalized = finalized

    return derived


AGGREGATION_SLOT_RE = re.compile(r"\bslot[=:]\s*(\d+)")


def _aggregation_events_from_logs(hosts_dir: Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for host_dir in sorted(hosts_dir.iterdir()):
        if not host_dir.is_dir():
            continue
        host = host_dir.name
        files = [
            *sorted(host_dir.glob("*.stdout")),
            *sorted(host_dir.glob("*.stderr")),
            *sorted(host_dir.glob("**/consensus.log")),
        ]
        for file_path in files:
            with open(file_path, errors="replace") as f:
                for line in f:
                    lower = line.lower()
                    if "aggregation" not in lower and "aggregate" not in lower:
                        continue
                    if "receive" not in lower and "received" not in lower:
                        continue
                    ts_ms = round(float(_STATS_SHADOW.parse_shadow_timestamp(line)) * 1000, 3)
                    slot_m = AGGREGATION_SLOT_RE.search(line)
                    slot = int(slot_m.group(1)) if slot_m else None
                    clean = _STATS_SHADOW.ANSI_RE.sub("", line).strip()
                    events.append(
                        {
                            "kind": "aggregation_received",
                            "host": host,
                            "slot": slot,
                            "ts_ms": ts_ms,
                            "message": clean[:240] or f"{host} received aggregation.",
                            "payload": {
                                "source": "text_pattern",
                                "file": str(file_path.relative_to(hosts_dir)),
                            },
                        }
                    )
    return events


def events_from_run(run_dir: str | Path) -> list[dict[str, Any]]:
    run_path = Path(run_dir)
    hosts_dir = _hosts_dir_for_run(run_path)
    if hosts_dir is None:
        return []

    nested = _STATS_SHADOW._read_host_events(hosts_dir)
    events: list[dict[str, Any]] = []
    for raw_kind, by_host in nested.items():
        for host, host_events in by_host.items():
            for event in host_events:
                events.append(_normalize_event(raw_kind, host, event))
            if raw_kind == "chain_status":
                events.extend(_derive_chain_delta_events(host, host_events))

    events.extend(_aggregation_events_from_logs(hosts_dir))
    return sorted(events, key=lambda e: (float(e.get("ts_ms") or 0.0), e.get("host") or ""))


def max_simulated_seconds_from_run(run_dir: str | Path) -> float:
    max_ms = 0.0
    for event in events_from_run(run_dir):
        max_ms = max(max_ms, float(event.get("ts_ms") or 0.0))
    return max_ms / 1000


def stats_from_run(run_dir: str | Path, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    run_path = Path(run_dir)
    if metadata is None:
        metadata_path = run_path / "run-metadata.json"
        metadata = json.loads(metadata_path.read_text()) if metadata_path.is_file() else {}
    with contextlib.redirect_stdout(io.StringIO()):
        return _STATS_SHADOW.collect_stats(str(run_path), metadata)
