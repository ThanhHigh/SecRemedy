import streamlit as st


def render(index: int, defaults: dict | None = None) -> dict:
    """Render form fields cho 1 server. Returns dict với SSH creds + scan params."""
    d = defaults or {}
    st.markdown(f"**Server {index + 1}**")
    col1, col2 = st.columns(2)
    with col1:
        ip = st.text_input("IP", value=d.get("ip", ""), key=f"ip_{index}")
        user = st.text_input("SSH User", value=d.get("user", "root"), key=f"user_{index}")
        scan_server = st.checkbox("Scan server này", value=d.get("scan_server", True), key=f"scan_{index}")
    with col2:
        port = st.number_input("SSH Port", min_value=1, max_value=65535, value=d.get("port", 22), key=f"port_{index}", step=1)
        password = st.text_input("SSH Password", value=d.get("pass", ""), type="password", key=f"pass_{index}")
        strict_private = st.checkbox("Strict private IP", value=d.get("strict_private", False), key=f"strict_{index}")

    ports_raw = st.text_input(
        "Authorized Ports (phân cách bằng dấu phẩy)",
        value=", ".join(str(p) for p in d.get("authorized_ports", [80, 443])),
        key=f"ports_{index}",
    )
    ips_raw = st.text_input(
        "Authorized IPs/CIDRs (phân cách bằng dấu phẩy)",
        value=", ".join(d.get("authorized_ips", ["127.0.0.1"])),
        key=f"ips_{index}",
    )

    authorized_ports = [int(p.strip()) for p in ports_raw.split(",") if p.strip().isdigit()]
    authorized_ips = [ip_s.strip() for ip_s in ips_raw.split(",") if ip_s.strip()]

    return {
        "ip": ip.strip(),
        "port": int(port),
        "user": user.strip(),
        "pass": password,
        "scan_server": scan_server,
        "strict_private": strict_private,
        "authorized_ports": authorized_ports,
        "authorized_ips": authorized_ips,
    }
