"""Shared time and slot helpers for Shadow dashboard code."""

from __future__ import annotations

import math

SHADOW_EPOCH = 946684800
SHADOW_GENESIS_TIME = 946684860
GENESIS_DELAY_SECONDS = SHADOW_GENESIS_TIME - SHADOW_EPOCH
SLOT_SECONDS = 4


def chain_slot_from_simulated_seconds(simulated_seconds: float | int | None) -> int:
    if simulated_seconds is None:
        return 0
    chain_seconds = max(0.0, float(simulated_seconds) - GENESIS_DELAY_SECONDS)
    return max(0, int(math.floor(chain_seconds / SLOT_SECONDS)))


def max_chain_slot_for_duration(duration_seconds: float | int | None) -> int:
    if duration_seconds is None:
        return 0
    return chain_slot_from_simulated_seconds(float(duration_seconds))
