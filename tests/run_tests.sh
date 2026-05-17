#!/bin/bash
set -e

PROJECT_ROOT=$(pwd)
TMP_DIR="$PROJECT_ROOT/tmp"
INTEGRATION_DIR="$PROJECT_ROOT/tests/integration"
CONFIG_DIR="$PROJECT_ROOT/tests/configs"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "1. Dọn/chuẩn bị tmp/..."
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

echo "2. Lấy nginx_raw_<port> từ các folder con của *_compliant sang tmp/raw_configs/<port>/..."
RAW_CONFIGS_DIR="$TMP_DIR/raw_configs"
mkdir -p "$RAW_CONFIGS_DIR"
# Copy mỗi thư mục nginx_raw_<port> vào tmp/raw_configs/<port>/
for src in "$INTEGRATION_DIR"/*_compliant/*/nginx_raw_*; do
    [ -d "$src" ] || continue
    port="${src##*/nginx_raw_}"
    dest="$RAW_CONFIGS_DIR/$port"
    mkdir -p "$dest"
    cp -r "$src"/. "$dest/"
done

export PYTHONPATH="$PROJECT_ROOT"

echo "3. Bắt đầu test..."

echo "-> Chạy Parser (Before remediation)..."
python -m core.scannerEng.parser --config "$CONFIG_DIR/before_remediation.json"

echo "-> Chạy Scanner (Before remediation)..."
python -m core.scannerEng.scanner --config "$CONFIG_DIR/before_remediation.json"

echo "-> Chạy RemedyEng..."
# python "$SCRIPT_DIR/resolve_symlinks.py"
python "$SCRIPT_DIR/run_remedy.py"

HARDENED_DIR="$TMP_DIR/hardened_configs"
if [ ! -d "$HARDENED_DIR" ] || [ -z "$(ls -A "$HARDENED_DIR" 2>/dev/null)" ]; then
    echo "[!] Bỏ qua bước scan-after: chưa thấy $HARDENED_DIR/<port>/. RemedyEng chưa sinh hardened configs?"
else
    echo "4. Re-scan hardened configs..."

    echo "-> Chạy Parser (After remediation)..."
    python -m core.scannerEng.parser --phase after

    echo "-> Chạy Scanner (After remediation)..."
    python -m core.scannerEng.scanner --phase after
fi

echo "5. Xong! Xem output trong tmp/contracts (before) và tmp/contracts/*_after (after)."
