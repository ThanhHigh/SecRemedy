#!/bin/bash
set -e

PROJECT_ROOT=$(pwd)
TMP_DIR="$PROJECT_ROOT/tmp"
INTEGRATION_DIR="$PROJECT_ROOT/tests/integration"
CONFIG_DIR="$PROJECT_ROOT/tests/configs"

echo "1. Dọn/chuẩn bị tmp/..."
rm -rf "$TMP_DIR"
mkdir -p "$TMP_DIR"

echo "2. Lấy nginx_raw_* từ *_uncomply sang tmp/..."
# Copy mọi thư mục con (nginx_raw_...) nằm trong các thư mục *_uncomply/ vào tmp/
find "$INTEGRATION_DIR" -type d -name "*_uncomply" -exec cp -r {}/. "$TMP_DIR/" \;

export PYTHONPATH="$PROJECT_ROOT"

echo "3. Bắt đầu test..."

echo "-> Chạy Parser (Before remediation)..."
python -m core.scannerEng.parser --config "$CONFIG_DIR/before_remediation.json"

echo "-> Chạy Scanner (Before remediation)..."
python -m core.scannerEng.scanner --config "$CONFIG_DIR/before_remediation.json"

# echo "-> Chạy RemedyEng..."
# python -m core.remedyEng.run_remedy --config "$CONFIG_DIR/config_input_remedy_toFinal.json"

# echo "-> Chạy Scanner (After)..."
# python -m core.scannerEng.scanner --config "$CONFIG_DIR/config_input_scanner_after_toFinal.json"

echo "4. Xong! Xem output trong tmp/contracts và điểm trên terminal."
