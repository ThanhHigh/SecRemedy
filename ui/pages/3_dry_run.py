import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.utils import state, file_io, path_helpers
from ui.utils import engine_runner
from ui.components import diff_viewer

st.set_page_config(page_title="Dry Run", layout="wide")
st.title("Bước 3 — Dry Run")

if not state.step2_done():
    st.warning("Hoàn thành Bước 2 — Scan Results trước.")
    st.stop()

servers = state.get("servers_config", {}).get("servers", [])
active_servers = [s for s in servers if s.get("scan_server", True)]

if st.button("Chạy Dry Run", type="primary", disabled=state.step3_done()):
    dry_run_results = {}
    all_ok = True

    for s in active_servers:
        port = s["port"]
        with st.spinner(f"Dry run server port {port}..."):
            try:
                result = engine_runner.run_dry_run(port, s)
                dry_run_results[port] = result
                st.subheader(f"Server {s['ip']}:{port}")
                diff_viewer.render(result)
            except Exception as e:
                st.error(f"Port {port}: Lỗi dry run — {e}")
                all_ok = False

    if all_ok:
        state.set("dry_run_done", True)
        state.set("dry_run_results", dry_run_results)
        state.clear_downstream("dry_run_done")
        st.success("Dry run hoàn tất. Chuyển sang **Bước 4 — Execute**.")
        st.rerun()

elif state.step3_done():
    dry_run_results = state.get("dry_run_results", {})
    for s in active_servers:
        port = s["port"]
        if port in dry_run_results:
            st.subheader(f"Server {s['ip']}:{port}")
            diff_viewer.render(dry_run_results[port])

    st.info("Dry run đã xong. Chuyển sang **Bước 4 — Execute**.")
