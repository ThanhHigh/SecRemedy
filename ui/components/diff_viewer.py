import streamlit as st


def render(dry_run_result: dict) -> None:
    """Hiển thị unified diff từ dry_run result."""
    status = dry_run_result.get("status", "")
    file_diffs = dry_run_result.get("file_diffs", {})
    diff_text = dry_run_result.get("diff", "")

    if status == "no_changes":
        st.success("Không có thay đổi cần áp dụng.")
        return

    if not file_diffs and not diff_text:
        st.warning("Không có diff data.")
        return

    if file_diffs:
        for file_path, diff in file_diffs.items():
            with st.expander(f"📄 {file_path}", expanded=False):
                st.code(diff, language="diff")
    elif diff_text:
        st.code(diff_text, language="diff")

    output_files = dry_run_result.get("output_files", [])
    if output_files:
        st.caption(f"Hardened files: {len(output_files)} file(s)")
