# SecRemedy: Nginx Configuration Security Assessment & Auto-Remediation

## Tổng quan dự án (Overview)

**SecRemedy** là ứng dụng DevSecOps tự động hóa đánh giá (assessment) và khắc phục (remediation) cấu hình Nginx theo tiêu chuẩn **CIS Nginx Benchmarks**.

### Bản chất: Hardening, không phải sửa lỗi cú pháp

- **Mục tiêu:** Thắt chặt bảo mật (Hardening) dựa trên khuyến nghị "Best Practice" — không đơn thuần là config bug fixing.
- Nginx vẫn chạy bình thường dù không tuân thủ đầy đủ, nhưng tồn tại rủi ro bảo mật.
- Dùng thuật ngữ **"Khuyến nghị"** (không phải "Luật") vì Hardening linh hoạt, cho phép tùy biến theo nghiệp vụ.

Mục tiêu cốt lõi: quy trình **"Safe Auto-Remediation"** — áp dụng Hardening hiệu quả, đảm bảo zero-downtime nhờ kiểm tra cú pháp Nginx tự động trước khi ghi đè.

## Trạng thái Phát triển (Development Status)

| Engine             |     Trạng thái     | Ghi chú                                                    |
| ------------------ | :----------------: | ---------------------------------------------------------- |
| Scanner Engine     |   ✅ Hoàn thành    | 12 Detector CIS đầy đủ, JSON Contract output               |
| Remediation Engine | 🔄 Integration test | 6/6 bước impl, pipeline end-to-end chạy qua `run_tests.sh` |
| Frontend / API     |  ⏳ Chưa bắt đầu   | FastAPI + Streamlit/Vue (kế hoạch)                         |

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
- **JSON Contract & Điểm tuân thủ:** Xuất báo cáo kèm Compliance Score. Mỗi vi phạm sinh JSON Contract chứa hành động sửa (`add`, `replace`, `delete`) + `exact_path` trên AST + `line` number.

### 2. Trình Tự động Khắc phục (Remediation Engine) — 🔄 Integration testing

> **Nguyên tắc cốt lõi:** Remedy Engine **không** tự tìm lỗi, **không** tự quyết định cách sửa. Nó chỉ đọc và thực thi đúng các instruction đã được Scanner mã hóa sẵn trong `scan_result_<port>.json`.

Mỗi vi phạm trong `scan_result_<port>.json` chứa một mảng `remediations[]` — danh sách lệnh chi tiết Remedy Engine thực thi tuần tự:

```json
"remediations": [
  {
    "action": "add",
    "directive": "server_tokens",
    "args": ["off"],
    "line": 17,
    "logical_context": ["http"],
    "exact_path": ["config", 0, "parsed", 6, "block"]
  }
]
```

**Pipeline thực thi của Remedy Engine (6 bước):**

1. **Đọc scan_result (Reader)** — Load `scan_result_<port>.json` từ `tmp/contracts/scan_result/`. Với mỗi `uncompliance`, xếp hàng từng item trong `remediations[]`.
2. **Định vị AST (Locator)** — Dùng `exact_path` để điều hướng chính xác đến node cần thao tác trong cây AST JSON (đã được crossplane parse sẵn). Không cần re-parse hay phân tích logic.
3. **Tiêm thay đổi (Injector)** — Thực thi `action`:
   - `add` → chèn directive/block mới vào đúng vị trí trong AST
   - `replace` → xóa directive cũ, chèn directive mới tại node đó
   - `delete` → xóa node đó khỏi AST
4. **Dựng lại config (Builder)** — `crossplane.build()` serialize AST đã chỉnh thành text Nginx config (`.conf`). Lưu ra `tmp/hardened_configs/<port>/`.
5. **Sinh diff (Diff Generator)** — So sánh original AST vs hardened AST qua `crossplane.build()` + `difflib.unified_diff()` — đảm bảo diff chỉ phản ánh thay đổi ngữ nghĩa, không bị ảnh hưởng bởi format. Gửi lên Frontend UI để user review.
6. **Thực thi (Executor)** — Chỉ chạy sau khi Approve Gate mở:
   - Backup: `cp -R /etc/nginx/ /etc/nginx.bak/` trên server
   - SFTP push hardened config lên `/etc/nginx/*` (hỗ trợ selective push theo `approved_files`)
   - Không chạy `nginx -s reload` (nằm ngoài scope Executor)

**Logic đặc biệt trong dry_run():**

- **Sort theo `exact_path` DESC:** Các remediation tại index cao trong cùng parent list chạy trước → tránh index-shift khi delete/insert.
- **Skip-and-log:** Item có `exact_path` không hợp lệ (Scanner bug) được log + bỏ qua thay vì crash cả batch.
- **`sites-enabled` → `sites-available` rewrite:** Toàn bộ AST được rewrite token `sites-enabled` thành `sites-available` (Nginx convention: `sites-available` giữ file thật, `sites-enabled` chỉ symlink).
- **Remote base marker:** Tính common parent của tất cả config file (vd `/etc/nginx`), lưu vào `tmp/hardened_configs/<port>/.remote_base` để `execute()` tái tạo đường dẫn remote khi SFTP push.
- **Modified AST dump:** Snapshot AST sau inject + rewrite ghi ra `tmp/contracts/mod_asts/mod_ast_<port>.json` để debug/audit.

**Approve Gate** nằm giữa Step 5 và Step 6 — Gate chỉ mở khi **user chủ động nhấn Approve** trên UI, không tự động.

**Trạng thái Remediation trong DB:**

| Trạng thái | Điều kiện |
| :--------: | --------- |
| `pending`  | Dry-Run xong, chờ Approve |
| `approved` | User nhấn Approve |
| `applied`  | Executor push thành công |
| `failed`   | SSH lỗi hoặc SFTP lỗi |

**File I/O Mapping:**

| Vai trò         | Đường dẫn |
| :-------------: | --------- |
| **INPUT**       | `tmp/contracts/scan_result/scan_result_<port>.json` |
| **INPUT**       | `tmp/contracts/parsers_output/parser_output_<port>.json` |
| **WORK**        | `tmp/hardened_configs/<port>/` |
| **DEBUG/AUDIT** | `tmp/contracts/mod_asts/mod_ast_<port>.json` |
| **OUTPUT**      | `/etc/nginx/*` trên target server |
| **BACKUP**      | `/etc/nginx.bak/*` trên target server |

### 3. Quy trình Khắc phục An toàn (Safe Remediation Workflow)

Zero-downtime đảm bảo bởi pipeline nghiêm ngặt:

1. **Pre-check:** Backend SSH vào server, chạy `nginx -t`. Fail → trả lỗi về UI, dừng toàn bộ.
2. **Dry-Run & Diff:** Sinh Unified Diff (gốc vs. hardened) → hiển thị lên Frontend UI để user review.
3. **Approve Gate:** User nhấn Approve → Gate mở → Executor chạy. Không approve → không ghi file.
4. **Backup & Apply:** Executor backup `/etc/nginx/` trước, sau đó SFTP push hardened config lên server (không reload).

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

| Folder         | Số vi phạm | Số test cases | Test IDs         | Tiến độ   |
| -------------- | :--------: | :-----------: | ---------------- | :-------: |
| `0_compliant`  |     0      |       5       | 2220 → 2224      |  5/5 ✅   |
| `1_compliant`  |     1      |      12       | 2226 → 2237      | 12/12 ✅  |
| `2_compliant`  |     2      |       3       | 2225, 2238–2239  |  3/3 ✅   |
| `3_compliant`  |     3      |       3       | 2240 → 2242      |  3/3 ✅   |
| `4_compliant`  |     4      |       3       | 2243 → 2245      |  3/3 ✅   |
| `5_compliant`  |     5      |       3       | 2246 → 2248      |  3/3 ✅   |
| `6_compliant`  |     6      |       3       | 2249 → 2251      |  3/3 ✅   |
| `7_compliant`  |     7      |       3       | 2252 → 2254      |  3/3 ✅   |
| `8_compliant`  |     8      |       3       | 2255 → 2257      |  3/3 ✅   |
| `9_compliant`  |     9      |       3       | 2258 → 2260      |  3/3 ✅   |
| `10_compliant` |    10      |       3       | 2261 → 2263      |  3/3 ✅   |
| `11_compliant` |    11      |       3       | 2264 → 2266      |  3/3 ✅   |
| `12_compliant` |    12      |       6       | 2267 → 2272      |  6/6 ✅   |

**6 Preset Nginx cấu hình thực tế:**

| #   | Preset                    | Mô tả                                                             |
| --- | ------------------------- | ----------------------------------------------------------------- |
| 1   | Nginx-Django-uWSGI        | Reverse proxy cho Django app qua uWSGI, SSL + subfolder redirects |
| 2   | Nginx-Frontend-SPA-CDN    | Serve SPA tĩnh + CDN server block cho static assets               |
| 3   | Nginx-SPA-PHP-FPM         | SPA frontend + PHP-FPM backend cho API routes, SSL                |
| 4   | Nginx-WordPress-PHP-FPM   | WordPress chuẩn dùng PHP-FPM, SSL + security configs              |
| 5   | Nginx-Magento-PHP-FPM-CDN | Magento 2 nâng cao: PHP-FPM + SSL + CDN block                     |
| 6   | Nginx-NodeJS-Proxy        | Reverse proxy đơn giản → Node.js app trên cổng 3000, SSL          |

Mỗi folder chứa nhiều `nginx_raw_<port>/`. `run_tests.sh` copy toàn bộ vào `tmp/` và chạy pipeline đầy đủ.

## Cấu trúc Thư mục (Directory Structure)

```text
SecRemedy/
├── core/                           # Mã nguồn chính
│   ├── recom_registry.py           # Metadata & registry 12 khuyến nghị CIS
│   ├── contracts/                  # Config JSON dùng chung cho engines
│   │   └── before_remediation.json # Batch config: SSH creds + scan params cho mọi port
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
│   └── remedyEng/                  # Engine sinh bản vá và áp dụng [🔄 integration test]
│       ├── remedy_engine.py        # Orchestrator — dry_run() + execute()
│       ├── reader.py               # Step 1 — Load scan_result.json → RemediationItem[]
│       ├── locator.py              # Step 2 — Navigate exact_path trong AST
│       ├── injector.py             # Step 3 — Apply add/replace/delete trên AST
│       ├── builder.py              # Step 4 — crossplane.build() → hardened config files
│       ├── diff_generator.py       # Step 5 — AST-based unified diff (original vs hardened)
│       └── executor.py             # Step 6 — SSH backup + SFTP push
├── tests/
│   ├── integration/                # Tập cấu hình Nginx tĩnh theo mức vi phạm
│   │   ├── 0_compliant/            # 5 preset, 0 vi phạm (IDs: 2220–2224)
│   │   ├── 1_compliant/            # 12 preset, 1 vi phạm (IDs: 2226–2237)
│   │   ├── 2_compliant/            # 3 preset, 2 vi phạm (IDs: 2225, 2238–2239)
│   │   ├── ...                     # 3_compliant → 12_compliant
│   │   ├── docker-compose.yml      # 1 container nginx_sec_remedy_test (SSH:2222)
│   │   ├── Dockerfile              # Nginx + OpenSSH image
│   │   └── test_doc.md             # Checklist phân bổ test cases
│   ├── configs/                    # Config JSON cho batch mode
│   │   └── before_remediation.json # Input chính cho toàn bộ pipeline batch
│   ├── run_tests.sh                # Script chạy full pipeline: Parse → Scan → Remedy → Re-scan
│   ├── run_remedy.py               # Batch runner cho RemedyEngine (dry-run hoặc execute)
│   ├── resolve_symlinks.py         # Resolve Git symlinks thành file thật (Windows compat)
│   ├── check_mod_ast.py            # Debug/audit modified AST output
│   ├── generate_dumps.sh           # Script sinh dump từ tập cấu hình
│   └── conftest.py                 # Pytest fixtures dùng chung
├── docs/                           # Tài liệu học thuật
│   ├── architecture/               # Data flow diagrams
│   │   ├── general_data_flow.md    # Tổng quan luồng dữ liệu toàn hệ thống
│   │   └── frontend_data_flow.md   # Luồng dữ liệu tầng Frontend
│   └── recommendations/            # Rationale & Impact từng CIS rule
├── database/                       # Persistence layer
│   ├── models.py                   # SQLAlchemy ORM: Server, ScanResult, Remediation
│   └── test_db.py                  # Script kiểm tra khởi tạo DB
├── logs/
│   └── remedy_runs/                # Log từng port khi chạy batch remedy
├── tmp/                            # Output runtime (gitignored)
│   ├── raw_configs/<port>/         # Config Nginx copy từ tests/integration/
│   ├── contracts/
│   │   ├── parsers_output/         # AST gốc: parser_output_<port>.json
│   │   ├── scan_result/            # Kết quả scan: scan_result_<port>.json
│   │   ├── scan_report/            # Báo cáo dạng Markdown: scan_report_<port>.md
│   │   └── mod_asts/               # AST đã inject: mod_ast_<port>.json (debug/audit)
│   └── hardened_configs/<port>/    # Config đã hardened (directory per port)
├── notes/                          # Ghi chú phát triển
├── devsecops_nginx.db              # SQLite DB (runtime)
└── requirements.txt                # Python dependencies
```

## Kiến trúc Hệ thống (Architecture)

### Kiến trúc 3 tầng

```
[ Tầng 1: Frontend — Streamlit UI ]
  Dashboard: Score + danh sách vi phạm CIS
  Remediation UI: Dry-Run → Diff → Approve
        │  Click Scan / Dry-Run / Approve
        ▼
[ Tầng 2: Backend API — FastAPI ]
  POST /scan    →  nginx -t pre-check → Scanner Engine
  POST /dry-run →  nginx -t pre-check → Remediation Engine (Steps 1–5)
  POST /approve →  Approve Gate → Executor (Step 6)
        │
        ▼
[ Tầng 3: Core Engines ]
  Scanner Engine:      SSH Fetch → Crossplane Parse → CIS Evaluate → Score + SQLite
  Remediation Engine:  AST Locate → AST Inject → Rewrite → Build hardened → AST Diff
  Safe Pipeline:       SSH Backup → SFTP Push hardened config
        │
        ▼
[ Tầng 4: Infrastructure — SQLite ]
  Bảng Servers | ScanResults | Remediations
```

> **Pre-check `nginx -t`:** Mỗi endpoint `/scan` và `/dry-run` đều SSH vào server chạy `nginx -t` trước. Fail → trả lỗi về UI ngay, không chạy engine.

### Stack kỹ thuật

- **Backend Engine:** Python 3.10+
- **API Layer:** FastAPI
- **Frontend:** Streamlit (hoặc Vue/React)
- **Database:** SQLite + SQLAlchemy ORM
- **Thư viện cốt lõi:**
  - `paramiko 4.x` — SSH đọc/ghi file và chạy lệnh từ xa
  - `crossplane 0.5.x` — Parse Nginx config thành JSON/AST đệ quy + build lại text
  - `difflib` (stdlib) — Sinh Unified Code Diff (so sánh output của crossplane.build)
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

Không cần SSH hay Docker. Script tự copy cấu hình tĩnh từ `tests/integration/*_compliant/` vào `tmp/`, rồi chạy toàn bộ pipeline:

```bash
bash tests/run_tests.sh
```

**Pipeline đầy đủ:**
1. Parse → JSON AST (`parser_output_<port>.json`)
2. Scan → CIS violations (`scan_result_<port>.json`)
3. Remedy → hardened configs (`tmp/hardened_configs/<port>/`) + mod AST (`mod_ast_<port>.json`)
4. Re-parse hardened configs → AST mới
5. Re-scan → kiểm tra compliance score sau khi remedy

Output lưu tại `tmp/contracts/` (before) và `tmp/contracts/*_after` (after).

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
# Dry-run một port (Steps 1–5, không push)
python -m core.remedyEng.remedy_engine --dry-run --port 2226

# Dry-run toàn bộ port trong before_remediation.json
python tests/run_remedy.py

# Execute một port (Step 6, push lên server)
python -m core.remedyEng.remedy_engine --execute --port 2226 \
    --host 127.0.0.1 --ssh-port 2222 --user root --pass secret
```

#### Bước 5 — Re-scan hardened configs (after remediation)

```bash
# Parse hardened configs
python -m core.scannerEng.parser --phase after

# Scan hardened configs
python -m core.scannerEng.scanner --phase after
```

## Chạy Tests

### Full pipeline (offline, không cần SSH)

```bash
bash tests/run_tests.sh
```

Chạy: **Parse → Scan → Remedy → Re-parse → Re-scan** trên toàn bộ tập cấu hình tĩnh.
Log từng port lưu tại `logs/remedy_runs/remedy_<port>.log`.

### Kiểm tra phân bổ test cases

Xem `tests/integration/test_doc.md` để biết trạng thái từng nhóm test.

### Debug modified AST

```bash
python tests/check_mod_ast.py
```

Audit `tmp/contracts/mod_asts/mod_ast_<port>.json` — snapshot AST sau inject + rewrite, trước build.
