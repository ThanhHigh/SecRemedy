import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.utils import state

st.set_page_config(
    page_title="SecRemedy",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded",
)

with st.sidebar:
    st.title("🔒 SecRemedy")
    st.caption("Nginx CIS Auto-Remediation")
    st.divider()

    steps = [
        ("1 Server Config", state.step1_done()),
        ("2 Scan Results", state.step2_done()),
        ("3 Dry Run", state.step3_done()),
        ("4 Execute", bool(state.get("approved"))),
    ]
    for label, done in steps:
        icon = "✅" if done else "⬜"
        st.write(f"{icon} {label}")

st.title("SecRemedy — Nginx CIS Auto-Remediation")
st.markdown("""
Công cụ tự động đánh giá và hardening Nginx theo CIS Benchmarks.

**Luồng sử dụng:**
1. **Server Config** — Nhập SSH credentials + scan parameters
2. **Scan Results** — Pre-check nginx -t + quét CIS violations
3. **Dry Run** — Xem thay đổi sẽ áp dụng (Unified Diff)
4. **Execute** — Approve + push hardened config lên server

Chọn trang trong sidebar để bắt đầu.
""")
