import streamlit as st


def apply_global_styles():
    """Apply global CSS for UI styling. `scale` multiplies base font size."""
    st.markdown(
        f"""
        <style>
        /* target Streamlit sidebar and enlarge all text */
        section[data-testid="stSidebar"] * {{
            font-size: 1.2rem !important;
            line-height: 2rem !important;
        }}
        </style>
        """,
        unsafe_allow_html=True,
    )
