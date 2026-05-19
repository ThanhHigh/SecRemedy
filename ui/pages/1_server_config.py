import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from ui.utils import state, file_io, path_helpers
from ui.components import server_form

st.set_page_config(page_title="Server Config", layout="wide")
from ui.utils.style import apply_global_styles
apply_global_styles()
st.title("Bước 1 — Cấu hình Server")
st.caption("Nhập SSH credentials và scan parameters cho từng target server.")

num_servers = st.number_input("Số lượng server", min_value=1, max_value=20, value=1, step=1)

with st.form("server_config_form"):
    servers_data = []
    existing = state.get("servers_config", {}).get("servers", [])
    for i in range(int(num_servers)):
        defaults = existing[i] if i < len(existing) else None
        data = server_form.render(index=i, defaults=defaults)
        servers_data.append(data)
        if i < int(num_servers) - 1:
            st.divider()

    submitted = st.form_submit_button("Lưu & Tiếp tục →", type="primary")

if submitted:
    errors = []
    for i, s in enumerate(servers_data):
        if not s["ip"]:
            errors.append(f"Server {i+1}: IP không được để trống.")
        if not s["authorized_ports"]:
            errors.append(f"Server {i+1}: Authorized Ports không hợp lệ.")
        if not s["authorized_ips"]:
            errors.append(f"Server {i+1}: Authorized IPs không hợp lệ.")

    if errors:
        for err in errors:
            st.error(err)
    else:
        contract_servers = []
        for s in servers_data:
            port = s["port"]
            contract_servers.append({
                "ip": s["ip"],
                "port": port,
                "user": s["user"],
                "pass": s["pass"],
                "strict_private": s["strict_private"],
                "scan_server": s["scan_server"],
                "authorized_ports": s["authorized_ports"],
                "authorized_ips": s["authorized_ips"],
                "input_path": path_helpers.parser_output_path(port),
                "output_path": path_helpers.scan_result_path(port),
                "report_path": path_helpers.report_path(port),
            })

        contract = {"servers": contract_servers}
        file_io.save_json(contract, path_helpers.before_remediation_contract())

        state.clear_downstream("servers_config")
        state.set("servers_config", contract)
        st.success(f"Đã lưu config cho {len(contract_servers)} server(s). Chuyển sang **Bước 2 — Scan Results**.")
        st.rerun()

if state.step1_done():
    servers = state.get("servers_config", {}).get("servers", [])
    st.info(f"Đã config {len(servers)} server(s). Chuyển sang trang **2 Scan Results**.")
