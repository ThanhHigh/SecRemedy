import streamlit as st

_STEP_KEYS = [
    "servers_config",   # step 1 done
    "precheck_results", # step 2 precheck
    "scan_done",        # step 2 done
    "dry_run_done",     # step 3 done
    "approved",         # step 4 approved
]

_DOWNSTREAM: dict[str, list[str]] = {
    "servers_config":   ["precheck_results", "scan_done", "dry_run_done", "approved"],
    "scan_done":        ["dry_run_done", "approved"],
    "dry_run_done":     ["approved"],
}


def get(key: str, default=None):
    return st.session_state.get(key, default)


def set(key: str, val) -> None:
    st.session_state[key] = val


def clear_downstream(from_key: str) -> None:
    for k in _DOWNSTREAM.get(from_key, []):
        st.session_state.pop(k, None)


def step1_done() -> bool:
    return bool(get("servers_config"))


def step2_done() -> bool:
    return bool(get("scan_done"))


def step3_done() -> bool:
    return bool(get("dry_run_done"))
