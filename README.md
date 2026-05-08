# SecRemedy: Nginx Configuration Security Assessment & Auto-Remediation

## Tổng quan dự án (Overview)

**SecRemedy** là ứng dụng DevSecOps tự động hóa đánh giá (assessment) và khắc phục (remediation) cấu hình Nginx theo tiêu chuẩn **CIS Nginx Benchmarks**.

### Bản chất: Hardening, không phải sửa lỗi cú pháp

- **Mục tiêu:** Thắt chặt bảo mật (Hardening) dựa trên khuyến nghị "Best Practice" — không đơn thuần là config bug fixing.
- Nginx vẫn chạy bình thường dù không tuân thủ đầy đủ, nhưng tồn tại rủi ro bảo mật.
- Dùng thuật ngữ **"Khuyến nghị"** (không phải "Luật") vì Hardening linh hoạt, cho phép tùy biến theo nghiệp vụ.

Mục tiêu cốt lõi: quy trình **"Safe Auto-Remediation"** — áp dụng Hardening hiệu quả, đảm bảo zero-downtime nhờ kiểm tra cú pháp Nginx tự động trước khi ghi đè.

## Tính năng cốt lõi (Key Features)

Hai engine độc lập, hoạt động tuần tự, giao tiếp qua **JSON Contract** lưu trong `tmp/contracts/`.

### 1. Trình Đánh giá Bảo mật (Scanner Engine)

- **Thu thập tự động (SSH Fetcher):** Kết nối SSH (`paramiko`), đóng gói và tải về toàn bộ `/etc/nginx` để phân tích ngoại tuyến. Port SSH đọc động từ config JSON — không hardcode.
- **Phân tích cấu trúc đệ quy (Crossplane Parser):** Dùng `crossplane` chuyển đổi toàn bộ file `.conf` (kể cả lồng nhau qua `include`) thành AST JSON. Hỗ trợ chế độ batch qua `--config` JSON.
- **Phát hiện lỗ hổng (CIS Detectors):** **12 Detector** kế thừa `BaseRecom`, quét đệ quy qua AST (khối `http`, `server`, `location`) theo chuẩn CIS Nginx Benchmark:
  - Bóc tách số port IPv4/IPv6 (2.4.1), kiểm tra default server block (2.4.2), phát hiện thiếu `server_tokens`/`error_page` (2.5.1, 2.5.2), thiếu block chặn `.git` (2.5.3), v.v.
  - Giải quyết logic kế thừa Nginx (ví dụ: `proxy_set_header` ở `http` kế thừa xuống `location`).
  - Truy vết lỗi sâu trong các file lồng nhau (`conf.d/*.conf`).
- **JSON Contract & Điểm tuân thủ:** Xuất báo cáo kèm Compliance Score. Mỗi vi phạm sinh JSON Contract chứa hành động sửa (`add`, `modify`, `delete`, `add_block`) + `exact_path` trên AST.

### 2. Trình Tự động Khắc phục (Remediation Engine)

- **Chạy batch không tương tác:** Chế độ `--config` JSON cho phép chạy toàn bộ pipeline (parse → scan → remedy → export) trên nhiều cấu hình cùng lúc, không cần người dùng nhập gì.
- **Chỉnh sửa AST chính xác (AST Editor):** Định vị chính xác vị trí vi phạm trên AST, thực hiện sửa in-memory: `add`, `modify`, `delete`, `add_block` mà không phá cấu trúc file gốc.
- **Xuất cấu hình (Export Manager):** Dịch ngược AST đã vá thành thư mục cấu hình Nginx hoàn chỉnh (`nginx_remediate_<port>_v<N>/`), kèm normalization tự động (xóa `allow all` thừa, sửa default-server block).
- **Xem trước thay đổi (Dry-Run Code Diff):** Dùng `crossplane` dịch ngược AST → text, rồi `difflib` sinh Unified Diff. Người dùng đối chiếu từng dòng `+`/`-` trước khi approve.
- **12 Remedy** kế thừa `BaseRemedy` — tương ứng 1-1 với 12 Detector (241, 242, 251, 252, 253, 254, 32, 34, 411, 511, 531, 532).

### 3. Quy trình Khắc phục An toàn (Safe Remediation Workflow)

Zero-downtime đảm bảo bởi pipeline nghiêm ngặt:

1. **Sinh cấu hình tạm:** Build file cấu hình từ AST đã được sửa.
2. **Kiểm thử cú pháp:** Chạy `nginx -t -c <temp_file>` trên target host.
3. **Rollback / Reapply:** Nếu `nginx -t` fail → dừng, cho phép Rollback hoặc Reapply mà không ảnh hưởng server đang chạy.
4. **Áp dụng:** Chỉ khi `nginx -t` OK → ghi đè file gốc và reload dịch vụ.

## Môi trường Kiểm thử (Test Environment)

### Docker — Integration Test

1 container Nginx duy nhất (`nginx_sec_remedy_test`) phục vụ test integration:

| Port   | Mục đích             |
| :----: | -------------------- |
| `2222` | SSH (paramiko)       |
| `8080` | HTTP                 |
| `8443` | HTTPS                |

Container mount `./workspace:/etc/nginx` — pytest tự copy file cấu hình vào đây trước khi test.

### Tập cấu hình Nginx tĩnh (Offline Batch Test)

Bộ cấu hình Nginx tĩnh (không cần SSH/Docker) nằm trong `tests/integration/`, chia theo nhóm mức vi phạm:

| Folder                  | Số lỗi   | Mô tả                                         |
| ----------------------- | :------: | --------------------------------------------- |
| `0_to_1_uncomply`       | 0–1      | Gần sạch — dùng để đối chiếu, tránh false positive |
| `1_to_3_uncomply`       | 1–3      | Vi phạm nhẹ (3.2, 3.4, 2.5.3, 2.5.4, ...)   |
| `3_to_4_uncomply`       | 3–4      | Vi phạm vừa (3.2, 3.4, 2.4.1/2, 2.5.1, ...) |
| `10_to_12_uncomply`     | 10–12    | Vi phạm hết tất cả các rule                  |

Mỗi folder chứa nhiều `nginx_raw_<port>/` (ví dụ: `nginx_raw_2230`, `nginx_raw_2231`, ...). `run_tests.sh` copy toàn bộ vào `tmp/` và chạy pipeline.

## Cấu trúc Thư mục (Directory Structure)

```text
SecRemedy/
├── core/                           # Mã nguồn chính
│   ├── recom_registry.py           # Metadata & registry các khuyến nghị CIS
│   ├── scannerEng/                 # Engine quét và phân tích
│   │   ├── fetcher.py              # SSH fetcher — tải /etc/nginx qua paramiko
│   │   ├── parser.py               # Crossplane parser — .conf → JSON AST (hỗ trợ --config batch)
│   │   ├── scanner.py              # Điều phối scan — chạy tất cả Detector
│   │   ├── base_recom.py           # BaseRecom — class gốc cho mọi Detector
│   │   └── recommendations/        # 12 Detector (detector_241.py … detector_532.py)
│   └── remedyEng/                  # Engine sinh bản vá và áp dụng
│       ├── run_remedy.py           # Entry point — điều phối pipeline (TUI + batch)
│       ├── remediator.py           # Điều phối remedy — chạy tất cả Remedy
│       ├── ast_editor.py           # AST Editor — thao tác in-memory trên AST
│       ├── export_manager.py       # Export AST → thư mục nginx config + normalization
│       ├── diff_generator.py       # Sinh Unified Diff bằng difflib
│       ├── terminal_ui.py          # TUI tương tác — hiển thị diff, nhận approval
│       ├── base_remedy.py          # BaseRemedy — class gốc cho mọi Remedy
│       ├── debug_logger.py         # Logger debug nội bộ
│       └── recommendations/        # 12 Remedy (remediate_241.py … remediate_532.py)
├── tests/
│   ├── integration/                # Docker Compose + tập cấu hình Nginx tĩnh
│   │   ├── docker-compose.yml      # 1 container nginx_sec_remedy_test (SSH:2222)
│   │   ├── Dockerfile              # Nginx + OpenSSH image
│   │   ├── 0_to_1_uncomply/        # nginx_raw_22X0 — 0–1 lỗi
│   │   ├── 1_to_3_uncomply/        # nginx_raw_22X1, 22X4 — 1–3 lỗi
│   │   ├── 3_to_4_uncomply/        # nginx_raw_22X2, 22X3 — 3–4 lỗi
│   │   └── 10_to_12_uncomply/      # nginx_raw_22X9 — lỗi hết
│   ├── unit/
│   │   ├── scannerEng/             # 12 test file (test_detector_241.py … test_detector_532.py)
│   │   └── remedyEng/              # 12 test file remedy + test_export_manager + test_batch
│   ├── config_to_test/             # JSON config cho batch pipeline
│   │   ├── config_input_scanner_before_toFinal.json
│   │   ├── config_input_scanner_after_toFinal.json
│   │   └── config_input_remedy_toFinal.json
│   ├── run_tests.sh                # Script chạy toàn bộ pipeline batch (không cần SSH)
│   ├── conftest.py                 # Pytest fixtures dùng chung
│   └── test_document.md            # Checklist trạng thái các cấu hình test
├── docs/                           # Tài liệu học thuật
│   ├── architecture/               # Data flow diagrams
│   ├── recommendations/            # Rationale & Impact từng CIS rule
│   └── tests/                      # Kịch bản kiểm thử & edge cases
├── database/                       # Persistence layer
│   ├── models.py                   # SQLAlchemy ORM: Server, ScanResult, Remediation
│   └── test_db.py                  # Script kiểm tra khởi tạo DB
├── tmp/                            # Output runtime (gitignored)
│   ├── nginx_raw_<port>/           # Config Nginx tải về từ SSH
│   ├── contracts/
│   │   ├── parsers_output/         # AST gốc sau parse
│   │   ├── scan_result/            # Báo cáo lỗi JSON Contract từ Scanner
│   │   └── remediated_output/      # AST đã vá
│   └── remedies_output/            # Thư mục nginx config đã remediate
├── notes/                          # Ghi chú phát triển
├── devsecops_nginx.db              # SQLite DB (runtime)
└── requirements.txt                # Python dependencies
```

## Kiến trúc Hệ thống (Architecture)

- **Backend Engine:** Python 3.10+
- **Database:** SQLite + SQLAlchemy ORM
- **Thư viện cốt lõi:**
  - `paramiko 4.x` — SSH đọc/ghi file và chạy lệnh từ xa
  - `crossplane 0.5.x` — Parse Nginx config thành JSON/AST đệ quy
  - `difflib` (stdlib) — Sinh Unified Code Diff
  - `SQLAlchemy 2.x` — ORM layer cho SQLite
  - `pytest` + `pytest-cov` — Framework test và đo độ phủ

## Hướng dẫn Cài đặt (Installation)

### Yêu cầu

- Python 3.10+
- Docker & Docker Compose (chỉ cần cho test integration SSH)

### Các bước

```bash
# 1. Clone
git clone <repository_url>
cd SecRemedy

# 2. Tạo virtualenv
python -m venv venv
source venv/bin/activate

# 3. Cài dependencies
pip install -r requirements.txt

# 4. (Tùy chọn) Khởi động container Docker cho test SSH
cd tests/integration
docker compose up -d --build
cd ../..
```

## Hướng dẫn Sử dụng (Usage)

### Chạy toàn bộ pipeline batch (khuyến nghị)

Không cần SSH hay Docker. Script tự copy cấu hình tĩnh vào `tmp/`, chạy Parse → Scan → Remedy → Scan lại:

```bash
bash tests/run_tests.sh
```

Output lưu tại `tmp/contracts/` và `tmp/remedies_output/`.

---

### Chạy từng bước thủ công

#### Bước 1 — Fetch cấu hình Nginx từ SSH

```bash
# Fetch tất cả server theo config JSON
python -m core.scannerEng.fetcher --config <config.json>

# Hoặc fetch một server cụ thể
python -m core.scannerEng.fetcher -H <ip> -P <ssh_port> -u <user> -p <password>
```

#### Bước 2 — Parse → JSON AST

```bash
# Batch
python -m core.scannerEng.parser --config <config.json>

# Một port cụ thể
python -m core.scannerEng.parser -P <ssh_port>
```

#### Bước 3 — Scan theo CIS Benchmarks

```bash
# Batch
python -m core.scannerEng.scanner --config <config.json>

# Một port
python -m core.scannerEng.scanner --ssh-port <ssh_port>
```

#### Bước 4 — Remediation Engine

```bash
# Batch (không tương tác)
python -m core.remedyEng.run_remedy --config <config.json>

# TUI tương tác
python -m core.remedyEng.run_remedy
```

> **Lưu ý:** Chế độ TUI cần container Docker đang chạy. Batch mode dùng được với cấu hình tĩnh offline.

## Chạy Tests

### Unit tests

```bash
# Tất cả unit tests
python -m pytest tests/unit/ -q

# Chỉ scannerEng
python -m pytest tests/unit/scannerEng/ -q

# Chỉ remedyEng
python -m pytest tests/unit/remedyEng/ -q

# Với coverage
python -m pytest tests/unit/ --cov=core -q
```

### Integration pipeline test (offline batch)

```bash
bash tests/run_tests.sh
```
