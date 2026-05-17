"""
Replace Git-tracked symlinks (mode 120000) with the real file content of their target.
Useful on Windows where core.symlinks=false stores symlinks as plain text files
containing the target path.

Usage:
    python scripts/resolve_symlinks.py [--dry-run]
"""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path


def get_symlinks(repo_root: Path) -> list[Path]:
    out = subprocess.check_output(
        ["git", "ls-files", "-s"], cwd=repo_root, text=True
    )
    return [
        repo_root / line.split("\t", 1)[1]
        for line in out.splitlines()
        if line.startswith("120000 ")
    ]


def resolve(link: Path) -> Path | None:
    if link.is_symlink():
        target = os.readlink(link)
    else:
        target = link.read_text(encoding="utf-8", errors="ignore").strip()
    if not target:
        return None
    target_path = (link.parent / target).resolve()
    return target_path if target_path.is_file() else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    links = get_symlinks(repo_root)
    print(f"[*] Found {len(links)} symlink entries")

    ok = skipped = failed = 0
    for link in links:
        rel = link.relative_to(repo_root)
        target = resolve(link)
        if target is None:
            print(f"  [SKIP] {rel} — target not found")
            skipped += 1
            continue

        if args.dry_run:
            print(f"  [DRY ] {rel} <- {target.relative_to(repo_root)}")
            ok += 1
            continue

        try:
            if link.is_symlink():
                link.unlink()
            shutil.copyfile(target, link)
            print(f"  [OK  ] {rel} <- {target.relative_to(repo_root)}")
            ok += 1
        except Exception as e:
            print(f"  [FAIL] {rel}: {e}")
            failed += 1

    print(f"\nSummary: ok={ok} skipped={skipped} failed={failed}")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
