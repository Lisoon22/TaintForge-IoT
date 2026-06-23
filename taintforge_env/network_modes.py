from __future__ import annotations

from enum import StrEnum


class NetworkMode(StrEnum):
    NONE = "none"
    EMULATED = "emulated"
    REPLAY = "replay"
    BROKERED_FETCH = "brokered_fetch"
    BROKERED_RELAY = "brokered_relay"
    BROKERED_RECORD = "brokered_record"


ALIASES = {
    "controlled": NetworkMode.EMULATED,
}


def normalize_network_mode(
    value: str,
    *,
    has_network_dependencies: bool,
) -> NetworkMode:
    normalized = value.strip().lower()

    if normalized == "auto":
        return (
            NetworkMode.EMULATED
            if has_network_dependencies
            else NetworkMode.NONE
        )

    if normalized in ALIASES:
        return ALIASES[normalized]

    try:
        return NetworkMode(normalized)
    except ValueError as exc:
        supported = ", ".join(mode.value for mode in NetworkMode)
        raise ValueError(
            f"Unsupported network mode: {value}. "
            f"Supported: auto, controlled, {supported}"
        ) from exc


def requires_egress_policy(mode: NetworkMode) -> bool:
    return mode in {
        NetworkMode.BROKERED_FETCH,
        NetworkMode.BROKERED_RELAY,
    }


def is_live_egress_mode(mode: NetworkMode) -> bool:
    return requires_egress_policy(mode)



def requires_record_policy(mode: NetworkMode) -> bool:
    return mode == NetworkMode.BROKERED_RECORD
