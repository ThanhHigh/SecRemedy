import streamlit as st
import pandas as pd


def render(scan_result: dict) -> None:
    score = scan_result.get("compliance_score", 0)
    recs = scan_result.get("recommendations", [])

    col1, col2 = st.columns(2)
    col1.metric("Compliance Score", f"{score:.1f}%")
    col2.metric("Violations", sum(1 for r in recs if r.get("status") == "fail"))

    rows = []
    for r in recs:
        files = []
        for u in r.get("uncompliances", []):
            files.append(u.get("file", ""))
        rows.append({
            "Rule ID": r.get("id", ""),
            "Title": r.get("title", ""),
            "Status": r.get("status", "").upper(),
            "Files": ", ".join(files) if files else "—",
        })

    if not rows:
        st.info("Không có violation nào.")
        return

    df = pd.DataFrame(rows)

    def color_status(val):
        if val == "FAIL":
            return "color: red; font-weight: bold"
        if val == "PASS":
            return "color: green"
        return ""

    st.dataframe(df.style.map(color_status, subset=["Status"]), use_container_width=True)
