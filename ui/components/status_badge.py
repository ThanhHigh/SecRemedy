import streamlit as st


def render_precheck(port: int, result: dict) -> None:
    if result.get("ok"):
        st.success(f"Port {port}: nginx -t OK")
    else:
        st.error(f"Port {port}: nginx -t FAIL")
        st.code(result.get("stderr", ""), language="text")


def render_execute(port: int, result: dict) -> None:
    status = result.get("status", "")
    if status == "applied":
        st.success(f"Port {port}: Config đã được push thành công.")
    else:
        st.error(f"Port {port}: Execute thất bại.")
        err = result.get("error")
        if err:
            st.code(err, language="text")
