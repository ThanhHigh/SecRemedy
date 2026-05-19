import streamlit as st
from pathlib import Path


def _is_big_file(path: Path, size_threshold: int = 100 * 1024, line_threshold: int = 500) -> bool:
    try:
        if not path.exists() or not path.is_file():
            return False
        if path.stat().st_size > size_threshold:
            return True
        # fallback: count lines up to threshold
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for i, _ in enumerate(f, 1):
                if i > line_threshold:
                    return True
        return False
    except Exception:
        return False


def _local_path_for_remote(hardened_dir: str, remote_path: str) -> Path:
    base = Path(hardened_dir)
    marker = base / ".remote_base"
    try:
        if marker.exists():
            remote_base = marker.read_text(encoding="utf-8").strip()
            if remote_base and remote_path.startswith(remote_base):
                rel = Path(*Path(remote_path).parts[len(Path(remote_base).parts):])
            else:
                rel = Path(*Path(remote_path).parts[1:])
        else:
            rel = Path(*Path(remote_path).parts[1:])
        return base / rel
    except Exception:
        # best-effort fallback: use filename
        return next(base.rglob(Path(remote_path).name), base / Path(remote_path).name)


def render(dry_run_result: dict) -> None:
    """Hiển thị unified diff từ dry_run result.

    For large files (mime.types, big lists) show truncated preview + download
    instead of full unified diff to avoid huge UI output.
    """
    status = dry_run_result.get("status", "")
    file_diffs = dry_run_result.get("file_diffs", {})
    diff_text = dry_run_result.get("diff", "")
    hardened_dir = dry_run_result.get("hardened_dir")

    if status == "no_changes":
        st.success("Không có thay đổi cần áp dụng.")
        return

    if not file_diffs and not diff_text:
        st.warning("Không có diff data.")
        return

    # Whitelist of filenames that tend to be large or not useful as diffs
    big_name_whitelist = {"mime.types", "modules", "types"}

    if file_diffs:
        for file_path, diff in file_diffs.items():
            fname = Path(file_path).name
            with st.expander(f"📄 {file_path}", expanded=False):
                # If file known-big or diff huge, show preview of hardened file instead
                show_as_file = False
                if fname in big_name_whitelist:
                    show_as_file = True

                if not show_as_file:
                    # if diff too long, switch to file preview
                    if diff and len(diff) > 10_000:
                        show_as_file = True

                if show_as_file and hardened_dir:
                    local = _local_path_for_remote(hardened_dir, file_path)
                    if local.exists():
                        is_big = _is_big_file(local)
                        try:
                            with local.open("r", encoding="utf-8", errors="ignore") as f:
                                if is_big:
                                    # truncated preview
                                    preview_lines = []
                                    for i, line in enumerate(f, 1):
                                        preview_lines.append(line)
                                        if i >= 200:
                                            break
                                    st.code("".join(preview_lines), language="")
                                    st.info(f"Preview truncated at 200 lines. File size: {local.stat().st_size} bytes.")
                                else:
                                    st.code(f.read(), language="")
                        except Exception as e:
                            st.warning(f"Không thể đọc file hardened: {e}")
                        try:
                            with local.open("rb") as bf:
                                st.download_button("Download hardened file", bf.read(), file_name=fname)
                        except Exception:
                            pass
                    else:
                        # fallback to showing diff if local file missing
                        st.code(diff or "(no diff)", language="diff")
                else:
                    st.code(diff or "(no diff)", language="diff")
    elif diff_text:
        st.code(diff_text, language="diff")

    output_files = dry_run_result.get("output_files", [])
    if output_files:
        st.caption(f"Hardened files: {len(output_files)} file(s)")
