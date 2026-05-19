import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.utils import state
from ui.utils import engine_runner
from ui.components import status_badge

st.set_page_config(page_title="Execute", layout="wide")
from ui.utils.style import apply_global_styles
apply_global_styles()
st.title("Bước 4 — Approve & Execute")

if not state.step3_done():
    st.warning("Hoàn thành Bước 3 — Dry Run trước.")
    st.stop()

servers = state.get("servers_config", {}).get("servers", [])
active_servers = [s for s in servers if s.get("scan_server", True)]
dry_run_results = state.get("dry_run_results", {})

st.subheader("Tóm tắt thay đổi sẽ áp dụng")
total_files = 0
for s in active_servers:
    port = s["port"]
    dr = dry_run_results.get(port, {})
    n_files = len(dr.get("output_files", []))
    total_files += n_files
    status = dr.get("status", "unknown")
    if status == "no_changes":
        st.info(f"Server {s['ip']}:{port} — Không có thay đổi.")
    else:
        st.write(f"Server **{s['ip']}:{port}** — {n_files} file(s) sẽ được hardened.")

st.divider()

already_done = state.get("approved", False)

if already_done:
    st.success("Execute đã chạy xong.")
    execute_results = state.get("execute_results", {})
    for s in active_servers:
        port = s["port"]
        if port in execute_results:
            status_badge.render_execute(port, execute_results[port])
else:
    st.warning("Hành động này sẽ push hardened config lên các target server. Không thể hoàn tác.")

    col1, col2 = st.columns([1, 4])
    confirm = col1.checkbox("Tôi đã xem xét diff và xác nhận Approve")
    approved = col2.button(
        "Approve & Execute",
        type="primary",
        disabled=not confirm,
    )

    if approved and confirm:
        execute_results = {}
        all_ok = True

        for s in active_servers:
            port = s["port"]
            dr = dry_run_results.get(port, {})
            if dr.get("status") == "no_changes":
                execute_results[port] = {"status": "applied", "error": None}
                status_badge.render_execute(port, execute_results[port])
                continue

            ssh_creds = {
                "host": s["ip"],
                "port": port,
                "username": s["user"],
                "password": s["pass"],
            }
            with st.spinner(f"Executing port {port}..."):
                result = engine_runner.run_execute(port, ssh_creds)
                execute_results[port] = result
                status_badge.render_execute(port, result)
                if result.get("status") != "applied":
                    all_ok = False

        state.set("approved", True)
        state.set("execute_results", execute_results)

        if all_ok:
            st.success("Tất cả server đã được hardened thành công.")
        else:
            st.error("Một số server execute thất bại. Kiểm tra log bên trên.")
