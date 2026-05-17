# SecRemedy: Nginx Configuration Security Assessment & Auto-Remediation

## Tổng quan dự án (Overview)

**SecRemedy** là ứng dụng DevSecOps tự động hóa đánh giá (assessment) và khắc phục (remediation) cấu hình Nginx theo tiêu chuẩn **CIS Nginx Benchmarks**.

### Bản chất: Hardening, không phải sửa lỗi cú pháp

- **Mục tiêu:** Thắt chặt bảo mật (Hardening) dựa trên khuyến nghị "Best Practice" — không đơn thuần là config bug fixing.
- Nginx vẫn chạy bình thường dù không tuân thủ đầy đủ, nhưng tồn tại rủi ro bảo mật.
- Dùng thuật ngữ **"Khuyến nghị"** (không phải "Luật") vì Hardening linh hoạt, cho phép tùy biến theo nghiệp vụ.

Mục tiêu cốt lõi: quy trình **"Safe Auto-Remediation"** — áp dụng Hardening hiệu quả, đảm bảo zero-downtime nhờ kiểm tra cú pháp Nginx tự động trước khi ghi đè.

## Trạng thái Phát triển (Development Status)

| Engine             |     Trạng thái     | Ghi chú                                        |
| ------------------ | :----------------: | ---------------------------------------------- |
| Scanner Engine     |   ✅ Hoàn thành    | 12 Detector CIS đầy đủ, JSON Contract output   |
| Remediation Engine | 🔄 Đang phát triển | Cấu trúc thư mục tạo sẵn, logic chưa implement |
| Frontend / API     |  ⏳ Chưa bắt đầu   | FastAPI + Streamlit/Vue (kế hoạch)             |

## Tính năng cốt lõi (Key Features)

Hai engine độc lập, hoạt động tuần tự, giao tiếp qua **JSON Contract** lưu trong `tmp/contracts/`.

### 1. Trình Đánh giá Bảo mật (Scanner Engine) — ✅ Hoàn thành

- **Thu thập tự động (SSH Fetcher):** Kết nối SSH (`paramiko`), đóng gói và tải về toàn bộ `/etc/nginx` để phân tích ngoại tuyến. Port SSH đọc động từ config JSON — không hardcode.
- **Phân tích cấu trúc đệ quy (Crossplane Parser):** Dùng `crossplane` chuyển đổi toàn bộ file `.conf` (kể cả lồng nhau qua `include`) thành AST JSON. Hỗ trợ chế độ batch qua `--config` JSON.
- **Phát hiện lỗ hổng (CIS Detectors):** **12 Detector** kế thừa `BaseRecom`, quét đệ quy qua AST (khối `http`, `server`, `location`) theo chuẩn CIS Nginx Benchmark:
  - `2.4.1` — Listen port authorization (IPv4/IPv6 aware)
  - `2.4.2` — Default server block (catch-all) enforcement
  - `2.5.1` — `server_tokens off` validation
  - `2.5.2` — Custom error pages (không tham chiếu NGINX)
  - `2.5.3` — Block hidden files (`.git`, `.env`, v.v.)
  - `2.5.4` — Reverse proxy không tiết lộ backend headers
  - `3.2` — Access log enabled
  - `3.4` — IP forwarding headers (`X-Real-IP`, `X-Forwarded-For`)
  - `4.1.1` — HTTP → HTTPS redirect
  - `5.1.1` — IP allow/deny access control
  - `5.3.1` — `X-Content-Type-Options: nosniff`
  - `5.3.2` — Content Security Policy (CSP)
- **Logic nâng cao:**
  - Giải quyết kế thừa Nginx (`proxy_set_header` ở `http` kế thừa xuống `location`).
  - Truy vết lỗi sâu trong các file lồng nhau (`conf.d/*.conf`, `sites-enabled/*.conf`).
  - Phân tích `include` đệ quy để tránh false negative khi directive nằm ở snippet riêng.
- **JSON Contract & Điểm tuân thủ:** Xuất báo cáo kèm Compliance Score. Mỗi vi phạm sinh JSON Contract chứa hành động sửa (`add`, `modify`, `delete`, `add_block`) + `exact_path` trên AST + `line` number.

### 2. Trình Tự động Khắc phục (Remediation Engine) — 🔄 Đang phát triển

> **Nguyên tắc cốt lõi:** Remedy Engine **không** tự tìm lỗi, **không** tự quyết định cách sửa. Nó chỉ đọc và thực thi đúng các instruction đã được Scanner mã hóa sẵn trong `scan_result.json`.

Mỗi vi phạm trong `scan_result.json` chứa một mảng `remediations[]` — đây là danh sách lệnh chi tiết mà Remedy Engine phải thực thi tuần tự:

```json
"remediations": [
  {
    "action": "add",                         // Loại hành động: add | modify | delete | add_block
    "directive": "server_tokens",             // Tên directive cần thao tác
    "args": ["off"],                          // Giá trị mới (với action add/modify)
    "line": 17,                               // Số dòng tham chiếu trong file gốc
    "logical_context": ["http"],             // Ngữ cảnh Nginx (http / server / location)
    "exact_path": ["config", 0, "parsed", 6, "block"]  // Đường dẫn chính xác đến node trong AST
  }
]
```

**Pipeline thực thi của Remedy Engine (5 bước):**

1. **Đọc scan_result** — Load `scan_result.json` từ `tmp/contracts/scan_result/`. Với mỗi `uncompliance`, duyệt qua từng item trong `remediations[]`.
2. **Định vị AST (Locator)** — Dùng `exact_path` để điều hướng chính xác đến node cần thao tác trong cây AST JSON (đã được crossplane parse sẵn). Không cần re-parse hay phân tích logic.
3. **Tiêm thay đổi (Injector)** — Thực thi `action`:
   - `add` / `add_block` → chèn directive/block mới vào đúng vị trí trong AST
   - `modify` → cập nhật `args` của directive tại node đó
   - `delete` → xóa node đó khỏi AST
4. **Dựng lại config (Builder)** — Crossplane serialize AST đã chỉnh thành text Nginx config (`.conf`). Lưu ra file tạm.
5. **Sinh diff & Validate** — Dùng `difflib` sinh Unified Diff (gốc vs. đã sửa). Upload file tạm lên server, chạy `nginx -t -c <temp_file>` qua SSH. Chỉ tiến hành Apply nếu `nginx -t` trả về `syntax is ok`.

### 3. Quy trình Khắc phục An toàn (Safe Remediation Workflow)

Zero-downtime đảm bảo bởi pipeline nghiêm ngặt — chỉ kích hoạt sau khi Remedy Engine hoàn tất bước 1–4:

1. **Dry-Run & Diff:** Sinh Unified Diff (gốc vs. đã sửa theo instruction) → hiển thị lên Frontend UI để user review.
2. **Kiểm thử cú pháp:** Upload file tạm lên target host, chạy `nginx -t -c <temp_file>` qua SSH, đọc kết quả.
3. **Gate check:** `nginx -t` fail → dừng toàn bộ, báo lỗi, không động vào file thật trên server.
4. **Approve & Apply:** Chỉ khi `nginx -t` OK **và** user nhấn Approve trên UI → ghi cấu hình đã harden vào file mới + push lên target server. ( không có reload).

## Môi trường Kiểm thử (Test Environment)

### Docker — Integration Test (SSH)

1 container Nginx duy nhất (`nginx_sec_remedy_test`) phục vụ test qua SSH thật:

|  Port  | Mục đích       |
| :----: | -------------- |
| `2222` | SSH (paramiko) |
| `8080` | HTTP           |
| `8443` | HTTPS          |

Container mount `./workspace:/etc/nginx` — pytest tự copy file cấu hình vào đây trước khi test.

### Tập cấu hình Nginx tĩnh (Offline Batch Test)

Bộ cấu hình Nginx tĩnh (không cần SSH/Docker) nằm trong `tests/integration/`, chia theo số lỗi vi phạm:

| Folder        | Số vi phạm | Số test cases | Test IDs        | Tiến độ  |
| ------------- | :--------: | :-----------: | --------------- | :------: |
| `0_compliant` |     0      |       5       | 2220 → 2224     |  5/5 ✅  |
| `1_compliant` |     1      |      12       | 2226 → 2237     | 12/12 ✅ |
| `2_compliant` |     2      |       3       | 2225, 2238–2239 |  3/3 ✅  |
| `3_compliant` |     3      |       9       | 2240 → 2248     |  0/9 🔄  |
| `4_compliant` |     4      |       9       | 2249 → 2257     |  0/9 🔄  |

> Các test case có 5–12 vi phạm (`2258 → 2272`) đang được lên kế hoạch.

**6 Preset Nginx cấu hình thực tế:**

| #   | Preset                    | Mô tả                                                             |
| --- | ------------------------- | ----------------------------------------------------------------- |
| 1   | Nginx-Django-uWSGI        | Reverse proxy cho Django app qua uWSGI, SSL + subfolder redirects |
| 2   | Nginx-Frontend-SPA-CDN    | Serve SPA tĩnh + CDN server block cho static assets               |
| 3   | Nginx-SPA-PHP-FPM         | SPA frontend + PHP-FPM backend cho API routes, SSL                |
| 4   | Nginx-WordPress-PHP-FPM   | WordPress chuẩn dùng PHP-FPM, SSL + security configs              |
| 5   | Nginx-Magento-PHP-FPM-CDN | Magento 2 nâng cao: PHP-FPM + SSL + CDN block                     |
| 6   | Nginx-NodeJS-Proxy        | Reverse proxy đơn giản → Node.js app trên cổng 3000, SSL          |

Mỗi folder chứa nhiều `nginx_raw_<port>/`. `run_tests.sh` copy toàn bộ vào `tmp/` và chạy pipeline Parse → Scan.

## Cấu trúc Thư mục (Directory Structure)

```text
SecRemedy/
├── core/                           # Mã nguồn chính
│   ├── recom_registry.py           # Metadata & registry 12 khuyến nghị CIS
│   ├── scannerEng/                 # Engine quét và phân tích
│   │   ├── fetcher.py              # SSH fetcher — tải /etc/nginx qua paramiko
│   │   ├── parser.py               # Crossplane parser — .conf → JSON AST (hỗ trợ --config batch)
│   │   ├── scanner.py              # Điều phối scan — chạy tất cả Detector, tính Compliance Score
│   │   ├── base_recom.py           # BaseRecom — class gốc cho mọi Detector
│   │   └── recommendations/        # 12 Detector (detector_241.py … detector_532.py)
│   │       ├── detector_241.py     # CIS 2.4.1 — Listen port authorization
│   │       ├── detector_242.py     # CIS 2.4.2 — Default server block
│   │       ├── detector_251.py     # CIS 2.5.1 — server_tokens off
│   │       ├── detector_252.py     # CIS 2.5.2 — Custom error pages
│   │       ├── detector_253.py     # CIS 2.5.3 — Block hidden files
│   │       ├── detector_254.py     # CIS 2.5.4 — Hide backend headers
│   │       ├── detector_32.py      # CIS 3.2  — Access log enabled
│   │       ├── detector_34.py      # CIS 3.4  — IP forwarding headers
│   │       ├── detector_411.py     # CIS 4.1.1 — HTTP → HTTPS redirect
│   │       ├── detector_511.py     # CIS 5.1.1 — IP allow/deny
│   │       ├── detector_531.py     # CIS 5.3.1 — X-Content-Type-Options
│   │       └── detector_532.py     # CIS 5.3.2 — Content Security Policy
│   └── remedyEng/                  # Engine sinh bản vá và áp dụng [🔄 WIP]
├── tests/
│   ├── integration/                # Tập cấu hình Nginx tĩnh theo mức vi phạm
│   │   ├── 0_compliant/            # 5 preset, 0 vi phạm (IDs: 2220–2224)
│   │   ├── 1_compliant/            # 5 preset, 1 vi phạm (IDs: 2226–2237)
│   │   ├── 2_compliant/            # 6 preset, 2 vi phạm (IDs: 2225, 2238–2239)
│   │   ├── 3_compliant/            # 6 preset, 3 vi phạm [🔄 WIP]
│   │   ├── 4_compliant/            # 6 preset, 4 vi phạm [🔄 WIP]
│   │   ├── docker-compose.yml      # 1 container nginx_sec_remedy_test (SSH:2222)
│   │   ├── Dockerfile              # Nginx + OpenSSH image
│   │   └── test_doc.md             # Checklist phân bổ test cases
│   ├── configs/                    # Config JSON cho batch mode
│   ├── run_tests.sh                # Script chạy toàn bộ pipeline batch (Parse → Scan)
│   ├── generate_dumps.sh           # Script sinh dump từ tập cấu hình
│   └── conftest.py                 # Pytest fixtures dùng chung
├── docs/                           # Tài liệu học thuật
│   ├── architecture/               # Data flow diagrams
│   └── recommendations/            # Rationale & Impact từng CIS rule
├── src/                            # Tài liệu tổng quan + outline
│   ├── general.md
│   └── outline_v1.md
├── database/                       # Persistence layer
│   ├── models.py                   # SQLAlchemy ORM: Server, ScanResult, Remediation
│   └── test_db.py                  # Script kiểm tra khởi tạo DB
├── tmp/                            # Output runtime (gitignored)
│   ├── nginx_raw_<port>/           # Config Nginx tải về từ SSH
│   ├── contracts/
│   │   ├── parsers_output/         # AST gốc sau parse
│   │   └── scan_result/            # Báo cáo lỗi JSON Contract từ Scanner
│   └── hardened_configs/           # Config Nginx đã remediate [🔄 WIP]
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

Không cần SSH hay Docker. Script tự copy cấu hình tĩnh từ `tests/integration/*_compliant/` vào `tmp/`, rồi chạy Parse → Scan:

```bash
bash tests/run_tests.sh
```

Output JSON Contract lưu tại `tmp/contracts/scan_result/`.

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

> 🔄 **Đang phát triển.** Module `core/remedyEng/` đang được implement.

## Chạy Tests

### Integration pipeline test (offline, không cần SSH)

```bash
bash tests/run_tests.sh
```

Script chạy: **Parse → Scan** trên toàn bộ tập cấu hình tĩnh trong `tests/integration/*_compliant/`.
Kết quả in trực tiếp ra terminal và lưu tại `tmp/contracts/`.

### Kiểm tra phân bổ test cases

Xem `tests/integration/test_doc.md` để biết trạng thái từng nhóm test.
