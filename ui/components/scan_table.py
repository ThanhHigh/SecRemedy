import streamlit as st
import pandas as pd


def render(scan_result: dict) -> None:
    score = scan_result.get("compliance_score", 0)
    recs = scan_result.get("recommendations", [])
    failed_count = sum(1 for r in recs if r.get("status") == "fail")

    col1, col2 = st.columns(2)
    col1.metric("Compliance Score", f"{score:.1f}%")
    col2.metric("Violations", f"{failed_count}/12")

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
            return "color: red; font-weight: bold; font-size: 1.2em"
        if val == "PASS":
            return "color: green; font-weight: bold; font-size: 1.2em"
        return ""

    # 2. Build the styling using standard Pandas methods
    styled_df = (
        df.style
        .map(color_status, subset=["Status"])
        # Global properties for tables, headers, and cells
        .set_properties(**{
            "font-size": "1.2em",
            "padding": "6px 10px"
        })
        .set_table_styles([
            # Custom properties specific to Table Header (th)
            {"selector": "th", "props": [
                ("font-size", "1.2em"),
                ("font-weight", "bold")
            ]},
            # Tighten table spacing
            {"selector": "table", "props": [
                ("border-collapse", "collapse")
            ]}
        ])
        .hide(axis="index") # Drop the default dataframe index column
    )

    # Render it securely as HTML 
    st.markdown(styled_df.to_html(escape=False), unsafe_allow_html=True)
