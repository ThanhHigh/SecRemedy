#!/bin/bash
# Dùng Docker mount Nginx config để dump (nginx -T) thành 1 file duy nhất cho 3rd party tool.
echo "Bắt đầu dump Nginx config..."

for conf_dir in tests/integration/*_uncomply/*/; do
    if [ -f "${conf_dir}nginx.conf" ]; then
        echo "[+] Đang xử lý: $conf_dir"
        docker run --rm \
            -v "$(pwd)/${conf_dir}:/etc/nginx:ro" \
            nginx:latest nginx -T 2>/dev/null > "${conf_dir}nginx-dump.conf"
    fi
done

echo "Xong! Các file nginx-dump.conf đã sẵn sàng."