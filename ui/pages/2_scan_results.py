import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.utils import state, file_io, path_helpers
from ui.utils import engine_runner
from ui.components import scan_table, status_badge

st.set_page_config(page_title="Scan Results", layout="wide")
from ui.utils.style import apply_global_styles
apply_global_styles()
st.title("Bước 2 — Pre-check & Scan Results")

if not state.step1_done():
    st.warning("Hoàn thành Bước 1 — Server Config trước.")
    st.stop()

servers = state.get("servers_config", {}).get("servers", [])
active_servers = [s for s in servers if s.get("scan_server", True)]
# show_scan_tables = st.toggle("Hiển thị bảng scan", value=True)

st.caption(f"{len(active_servers)}/{len(servers)} server(s) được chọn để scan.")

if st.button("Chạy Pre-check + Scan", type="primary", disabled=state.step2_done()):
    precheck_results = {}
    all_ok = True

    st.subheader("Pre-check: nginx -t")
    with st.spinner("Đang kiểm tra nginx -t trên tất cả server..."):
        for s in active_servers:
            port = s["port"]
            result = engine_runner.run_precheck(s)
            precheck_results[port] = result
            status_badge.render_precheck(port, result)
            if not result["ok"]:
                all_ok = False

    state.set("precheck_results", precheck_results)

    if not all_ok:
        st.error("Một hoặc nhiều server FAIL nginx -t. Dừng — không thể tiếp tục scan.")
        st.stop()

    st.subheader("Scan CIS Benchmarks")
    scan_results = {}
    for s in active_servers:
        port = s["port"]
        with st.spinner(f"Đang fetch + parse + scan server port {port}..."):
            try:
                engine_runner.run_fetch_and_parse(s)
                result = engine_runner.run_scan(s)
                scan_results[port] = result
                # if show_scan_tables:
                #     st.markdown(f"### Server {s['ip']}:{port}")
                with st.expander(f"Server {s['ip']}:{port}", expanded=True):
                    scan_table.render(result)
            except Exception as e:
                st.error(f"Port {port}: Lỗi scan — {e}")
                all_ok = False

    if all_ok:
        state.set("scan_done", True)
        state.set("scan_results", scan_results)
        state.clear_downstream("scan_done")
        st.success("Scan hoàn tất. Chuyển sang **Bước 3 — Dry Run**.")
        st.rerun()

elif state.step2_done():
    st.subheader("Kết quả Scan (đã lưu)")
    scan_results = state.get("scan_results", {})
    precheck_results = state.get("precheck_results", {})

    for s in active_servers:
        port = s["port"]
        if port in precheck_results:
            status_badge.render_precheck(port, precheck_results[port])
        if port in scan_results:
            # if show_scan_tables:
            #     st.markdown(f"### Server {s['ip']}:{port}")
            with st.expander(f"Server {s['ip']}:{port}", expanded=False):
                scan_table.render(scan_results[port])

    st.info("Scan đã xong. Chuyển sang **Bước 3 — Dry Run**.")
