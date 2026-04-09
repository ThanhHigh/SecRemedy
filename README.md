# SecRemedy

**SecRemedy** là một công cụ tự động đánh giá bảo mật và khắc phục lỗi cấu hình cho Nginx, dựa trên các tiêu chuẩn **CIS Benchmark v3.0.0**. Dự án sử dụng `crossplane` để phân tích cấu hình Nginx thành định dạng JSON AST (Abstract Syntax Tree), tiến hành quét tự động tìm kiếm các điểm yếu, sinh ra báo cáo kèm đề xuất khắc phục, và cung cấp luồng Interactive Remediation an toàn với Unified Diff review.

---

## 🚀 Tính năng chính

- **Kiểm tra bảo mật tự động:** Đánh giá cấu hình Nginx dựa trên **10 quy tắc trọng điểm** của CIS Benchmark v3.0.0 (xem chi tiết tại [`first-10-recommendations.md`](docs/first-10-recommendations.md)).
- **Phân tích cấu hình (AST):** Ứng dụng `crossplane` để chuyển đổi tập tin `nginx.conf` sang định dạng JSON, giúp phân tích cấu trúc cấu hình một cách có hệ thống.
- **In-Memory Recommendation Registry:** Lưu trữ toàn bộ metadata của 10 quy tắc CIS trong bộ nhớ RAM bằng `dataclass(frozen=True)` và `Enum` ID, cho phép cả Scanner Engine và Remediation Engine truy xuất dữ liệu với độ phức tạp O(1).
- **Scanner Engine (Detector Pattern):** Kiến trúc `BaseRecom` cung cấp thuật toán duyệt đệ quy (Recursive Traversal) cây AST. Mỗi quy tắc CIS được triển khai thành một class Detector riêng biệt kế thừa `BaseRecom` và ghi đè hàm `evaluate()`. Tất cả **10 Detectors** đã triển khai hoàn chỉnh.
- **Remediation Engine (Interactive Diff Review):** Kiến trúc `BaseRemedy` + `Remediator` + `TerminalUI` + `ASTEditor`. Mỗi quy tắc CIS được triển khai thành một class Remediate riêng biệt kế thừa `BaseRemedy` và ghi đè hàm `remediate()`. Hỗ trợ luồng interactive: hiển thị thông tin → quyết định trước diff → nhập user input (nếu cần) → xem Unified Diff per-file → chấp nhận/từ chối → merge vào AST tổng.
- **Unified Diff Generation:** Module `diff_generator.py` sử dụng `difflib` + `crossplane.build()` để render AST thành Nginx config text, tạo unified diff dễ đọc cho mỗi file thay đổi. Fallback sang AST JSON diff khi render thất bại.
- **AST Editor:** Module `ast_editor.py` cung cấp các tiện ích thao tác trên cây AST: navigate by context path, append/insert/remove nodes, normalize file paths, và render AST sang config text hoặc JSON.
- **Môi trường giả lập Docker Mock Servers:** Tích hợp sẵn 2 container Nginx với các bộ vi phạm CIS khác nhau (Rule 1–5 và Rule 6–10), mount trực tiếp từ thư mục `tests/integration/` để dễ dàng cho việc phát triển và kiểm thử tự động.
- **Unit Testing (pytest):** Bộ test `pytest` cho các Detector thuộc Scanner Engine, kiểm tra cả `evaluate()` (isolated) và `scan()` (full pipeline) với synthetic AST payloads.
- **Quản lý dữ liệu tập trung:** Ứng dụng SQLAlchemy kết nối với SQLite (`devsecops_nginx.db`) để lưu trữ dữ liệu vòng đời máy chủ, kết quả quét, các quy tắc bị lỗi và tiến trình khắc phục.

---

## 📁 Cấu trúc dự án

```text
SecRemedy/
├── core/                                    # Các engine lõi xử lý logic DevSecOps
│   ├── recom_registry.py                    # In-Memory Registry: RecomID (Enum) + Recommendation (frozen dataclass)
│   ├── scannerEng/                          # Scanner Engine — Quét và đánh giá bảo mật
│   │   ├── base_recom.py                    # BaseRecom: Recursive AST traversal + abstract evaluate()
│   │   ├── fetcher.py                       # CLI: Tải cấu hình Nginx từ server qua SSH (Paramiko)
│   │   ├── parser.py                        # CLI: Phân tích nginx.conf sang JSON AST (dùng crossplane)
│   │   ├── scanner.py                       # CLI: Main Scanner Engine — orchestrate Detectors, tính compliance score
│   │   └── recommendations/                 # Thư mục chứa 10 class Detector (mỗi file = 1 CIS rule)
│   │       ├── detector_241.py              # Detector cho CIS 2.4.1 (Listen port)
│   │       ├── detector_242.py              # Detector cho CIS 2.4.2 (Unknown hostnames)
│   │       ├── detector_251.py              # Detector cho CIS 2.5.1 (Server tokens)
│   │       ├── detector_252.py              # Detector cho CIS 2.5.2 (Error/index pages)
│   │       ├── detector_253.py              # Detector cho CIS 2.5.3 (Hidden files)
│   │       ├── detector_31.py               # Detector cho CIS 3.1 (Detailed logging)
│   │       ├── detector_32.py               # Detector cho CIS 3.2 (Access logging)
│   │       ├── detector_33.py               # Detector cho CIS 3.3 (Error logging level)
│   │       ├── detector_34.py               # Detector cho CIS 3.4 (Proxy source IP)
│   │       └── detector_411.py              # Detector cho CIS 4.1.1 (HTTP → HTTPS redirect)
│   └── remedyEng/                           # Remediation Engine — Interactive Diff Review
│       ├── base_remedy.py                   # BaseRemedy: file-grouped AST remediation + diff generation
│       ├── remediator.py                    # Remediator: orchestrate all remedies, merge approved changes
│       ├── terminal_ui.py                   # TerminalUI (Singleton): CLI prompts, diff display, user decisions
│       ├── ast_editor.py                    # ASTEditor: navigate/modify AST by context path, render config text
│       ├── diff_generator.py                # Unified Diff + AST fallback diff helpers (difflib)
│       ├── run_remedy.py                    # CLI entry-point: interactive remediation flow
│       ├── debug_print.py                   # Debug print toggle utility
│       └── recommendations/                 # Thư mục chứa 10 class Remediate (mỗi file = 1 CIS rule)
│           ├── __init__.py
│           ├── remediate_241.py             # Remediate cho CIS 2.4.1 (Listen port)
│           ├── remediate_242.py             # Remediate cho CIS 2.4.2 (Unknown hostnames)
│           ├── remediate_251.py             # Remediate cho CIS 2.5.1 (Server tokens)
│           ├── remediate_252.py             # Remediate cho CIS 2.5.2 (Error/index pages)
│           ├── remediate_253.py             # Remediate cho CIS 2.5.3 (Hidden files)
│           ├── remediate_31.py              # Remediate cho CIS 3.1 (Detailed logging)
│           ├── remediate_32.py              # Remediate cho CIS 3.2 (Access logging)
│           ├── remediate_33.py              # Remediate cho CIS 3.3 (Error logging level)
│           ├── remediate_34.py              # Remediate cho CIS 3.4 (Proxy source IP)
│           └── remediate_411.py             # Remediate cho CIS 4.1.1 (HTTP → HTTPS redirect)
├── database/                                # Tầng persistence — ORM và script khởi tạo DB
│   ├── models.py                            # Định nghĩa ORM (SQLAlchemy): Server, ScanResult, FailedRule, Remediation
│   └── test_db.py                           # Script khởi tạo và seed mock data vào SQLite
├── contracts/                               # Data Contracts kết nối giữa quá trình Quét và Khắc phục
│   ├── scan_result.json                     # Scan Result Contract mẫu (legacy)
│   ├── scan_result_2221.json                # Scan Result Contract — VPS 1–5 (port 2221)
│   ├── scan_result_2222.json                # Scan Result Contract — VPS 6–10 (port 2222)
│   ├── parser_output_2221.json              # Parser output JSON (crossplane AST) từ VPS 1–5 (port 2221)
│   └── parser_output_2222.json              # Parser output JSON (crossplane AST) từ VPS 6–10 (port 2222)
├── docs/                                    # Tài liệu kỹ thuật và nghiên cứu học thuật
│   ├── first-10-recommendations.md          # 10 quy tắc CIS Benchmark chi tiết (Audit, Remediation, ...)
│   ├── Impacts.md                           # Phân tích tác động (Impact) của từng quy tắc CIS
│   ├── Rationales.md                        # Lý do áp dụng (Rationale) — cơ sở lý luận cho luận văn
│   ├── NOTES.md                             # Ghi chú nghiên cứu và quyết định thiết kế (academic notes)
│   ├── backend_data_flow.txt                # Sơ đồ luồng dữ liệu Core Engines
│   └── general_data_flow.txt                # Sơ đồ kiến trúc tổng thể 4 tầng (Frontend → Backend → Core → Infra)
├── tests/                                   # Bộ kiểm thử tự động
│   ├── integration/                         # Docker infrastructure + cấu hình Nginx giả lập
│   │   ├── Dockerfile                       # Build image Docker (Nginx 1.28, SSH, SSL giả lập)
│   │   ├── docker-compose.yml               # Khởi chạy cụm 2 servers Nginx giả lập (port 2221, 2222)
│   │   ├── vps-one-to-five/                 # VPS giả lập: Vi phạm Rule 1–5, tuân thủ Rule 6–10
│   │   │   ├── nginx.conf
│   │   │   ├── conf.d/
│   │   │   │   ├── emarket.me.conf
│   │   │   │   ├── admin.emarket.me.conf
│   │   │   │   ├── customer.emarket.me.conf
│   │   │   │   └── vendor.emarket.me.conf
│   │   │   ├── mime.types
│   │   │   ├── fastcgi_params
│   │   │   └── proxy_params
│   │   └── vps-six-to-then/                 # VPS giả lập: Vi phạm Rule 6–10, tuân thủ Rule 1–5
│   │       ├── nginx.conf
│   │       ├── conf.d/
│   │       │   ├── emarket.me.conf
│   │       │   ├── admin.emarket.me.conf
│   │       │   ├── customer.emarket.me.conf
│   │       │   └── vendor.emarket.me.conf
│   │       ├── mime.types
│   │       ├── fastcgi_params
│   │       └── proxy_params
│   └── unit/                                # Pytest unit tests
│       └── scannerEng/                      # Tests cho Scanner Engine Detectors
│           ├── test_detector_241.py          # Unit test: CIS 2.4.1 Detector
│           ├── test_detector_251.py          # Unit test: CIS 2.5.1 Detector
│           ├── test_detector_31.py           # Unit test: CIS 3.1 Detector
│           ├── test_detector_32.py           # Unit test: CIS 3.2 Detector
│           └── test_detector_33.py           # Unit test: CIS 3.3 Detector
|
├── conftest.py                              # Pytest root conftest (sys.path setup)
├── requirements.txt                         # Python dependencies (crossplane, paramiko, sqlalchemy, ...)
├── .gitignore                               # Loại trừ: venv/, tmp/, *.db, __pycache__/, backups/, notes/
└── README.md                                # Tổng quan dự án (File này)
```

---

## 🛠️ Hướng dẫn cài đặt & Khởi chạy

### 1. Chuẩn bị môi trường Python

```bash
# Tạo virtual environment
python -m venv venv
source venv/bin/activate

# Cài đặt tất cả dependencies
pip install -r requirements.txt
```

Danh sách các thư viện chính trong `requirements.txt`:

| Thư viện       | Vai trò                                               |
| -------------- | ----------------------------------------------------- |
| `crossplane`   | Phân tích cấu hình Nginx thành JSON AST               |
| `paramiko`     | Kết nối SSH để fetch/backup cấu hình từ server        |
| `sqlalchemy`   | ORM kết nối SQLite, quản lý dữ liệu vòng đời quét     |
| `cryptography` | Xử lý kết nối SSH an toàn (dependency của `paramiko`) |

### 2. Khởi tạo Cơ sở dữ liệu

Tiến hành tạo cấu trúc bảng cho SQLite:

```bash
python database/test_db.py
```

_(Hệ thống sẽ tự động khởi tạo file `devsecops_nginx.db` với các bảng dữ liệu `servers`, `scan_results`, `failed_rules`, `remediations` và seed mock data từ `contracts/scan_result.json`)_

**Sơ đồ ERD (Entity-Relationship):**

```
Server 1───* ScanResult 1───* FailedRule
                       1───1 Remediation
```

| Bảng           | Mô tả                                                                               |
| -------------- | ----------------------------------------------------------------------------------- |
| `servers`      | Thông tin server (IP, SSH user)                                                     |
| `scan_results` | Kết quả mỗi lần quét (compliance score, raw AST JSON, trạng thái)                   |
| `failed_rules` | Danh sách quy tắc CIS vi phạm (rule_id, severity, target_context)                   |
| `remediations` | Trạng thái luồng khắc phục (`pending_approval` → `approved` → `applied` / `failed`) |

### 3. Thiết lập Môi trường thử nghiệm Docker

Dự án SecRemedy sử dụng Docker để thiết lập môi trường test với 2 container Nginx. Cấu hình Docker nằm trong `tests/integration/`, mỗi container mount cấu hình trực tiếp:

| Container           | Mount Source                                | Mô tả                                    |
| ------------------- | ------------------------------------------- | ---------------------------------------- |
| `nginx_one_to_five` | `tests/integration/vps-one-to-five/` | Vi phạm CIS Rule 1–5, tuân thủ Rule 6–10 |
| `nginx_six_to_then` | `tests/integration/vps-six-to-then/` | Vi phạm CIS Rule 6–10, tuân thủ Rule 1–5 |

Yêu cầu hệ thống phải cài đặt sẵn **Docker** và **Docker Compose**.

**Quản lý containers:**

```bash
# Build và khởi động containers (chạy từ thư mục tests/integration/)
cd tests/integration && docker compose up -d --build

# Dừng containers
docker compose stop

# Khởi động lại containers
docker compose start

# Xóa containers
docker compose down
```

**Kiểm tra và Test:**

1. **Kiểm tra trạng thái containers:** Chạy lệnh sau để xem trạng thái, cả 2 container phải hiện chữ **Up**:

```bash
docker compose ps
```

2. **Kiểm tra kết nối SSH:**
   _Các kết nối SSH này sẽ được sử dụng cho Tool tự động kiểm tra bảo mật. Cả hai máy chủ đều hỗ trợ SSH với thông tin đăng nhập: User: `root`, Password: `root`._

- **Nginx VPS 1–5 (Vi phạm Rule 1–5):** HTTP (Port 8081), HTTPS (Port 8443), SSH (Port 2221)
  ```bash
  ssh root@localhost -p 2221
  ```
- **Nginx VPS 6–10 (Vi phạm Rule 6–10):** HTTP (Port 8082), HTTPS (Port 8444), SSH (Port 2222)
  ```bash
  ssh root@localhost -p 2222
  ```

**Xử lý sự cố:**

- **Containers không khởi động:** Chạy `docker compose logs` hoặc `docker compose logs nginx_one_to_five` / `nginx_six_to_then` để xem lỗi cụ thể.
- **Port đã được sử dụng:** Nếu port 2221 hoặc 2222 bị xung đột, chỉnh sửa file `tests/integration/docker-compose.yml` để thay đổi port mapping.

---

## 📡 Data Contracts

Data Contracts là giao diện dữ liệu JSON chính thức kết nối giữa Scanner Engine (Thành viên 1) và Remediation Engine (Thành viên 2). Tất cả các file contract được lưu trong thư mục `contracts/`.

### Scan Result Contract (`scan_result_<port>.json`)

Đây là output chính của Scanner Engine, chứa kết quả đánh giá bảo mật và danh sách các vi phạm kèm đề xuất khắc phục. Mỗi port tương ứng với một VPS giả lập:

- `scan_result_2221.json` — Kết quả quét VPS 1–5 (vi phạm Rule 1–5, compliance score ~40%)
- `scan_result_2222.json` — Kết quả quét VPS 6–10 (vi phạm Rule 6–10)

```json
{
  "scan_id": 1,
  "server_ip": "0.0.0.0",
  "compliance_score": 40,
  "created_at": "2026-04-03T09:38:14Z",
  "recommendations": [
    {
      "id": "2.5.1",
      "title": "Ensure server_tokens directive is set to off",
      "description": "...",
      "rationale": "...",
      "impact": "...",
      "status": "fail",
      "uncompliances": [
        {
          "file": "./tmp/nginx_raw_2221/nginx.conf",
          "remediations": [
            {
              "action": "replace",
              "context": ["config", 0, "parsed", 5, "block", 2],
              "directive": "server_tokens",
              "args": ["off"]
            }
          ]
        }
      ]
    },
    {
      "id": "3.1",
      "title": "Ensure detailed logging is enabled",
      "status": "pass",
      "uncompliances": []
    }
  ]
}
```

### Parser Output Contract (`parser_output_<port>.json`)

Output của `crossplane` chứa toàn bộ AST JSON của cấu hình Nginx đã phân tích (bao gồm tất cả các file `include` đệ quy).

---

## ⚙️ Scanner Engine (`core/scannerEng/`)

### Kiến trúc Detector Pattern

Scanner Engine sử dụng mô hình **Detector Pattern** với 3 thành phần chính:

| Thành phần                  | File                | Vai trò                                                   |
| --------------------------- | ------------------- | --------------------------------------------------------- |
| **Recommendation Registry** | `recom_registry.py` | In-memory store metadata CIS (Enum ID + frozen dataclass) |
| **Base Recommendation**     | `base_recom.py`     | Recursive AST traversal + abstract `evaluate()` template  |
| **Detector Classes**        | `recommendations/`  | Mỗi quy tắc CIS = 1 class kế thừa `BaseRecom`             |

**Detector Registry** (trong `scanner.py`):

```python
DETECTOR_REGISTRY: Dict[RecomID, Type[BaseRecom]] = {
    RecomID.CIS_2_4_1: Detector241,
    RecomID.CIS_2_4_2: Detector242,
    RecomID.CIS_2_5_1: Detector251,
    RecomID.CIS_2_5_2: Detector252,
    RecomID.CIS_2_5_3: Detector253,
    RecomID.CIS_3_1:   Detector31,
    RecomID.CIS_3_2:   Detector32,
    RecomID.CIS_3_3:   Detector33,
    RecomID.CIS_3_4:   Detector34,
    RecomID.CIS_4_1_1: Detector411,
}
```

**Luồng hoạt động:**

```
Parser Output (AST JSON)
    │
    ▼  BaseRecom.scan(parser_output)
[Duyệt từng file .conf trong AST]
    │
    ▼  BaseRecom._traverse_ast(directives, filepath, context)
[Duyệt đệ quy từng directive, theo dấu context path]
    │
    ▼  DetectorXXX.evaluate(directive, filepath, context)
[Class con đánh giá: trả về violation dict hoặc None]
    │
    ▼
[Danh sách uncompliances cho Scan Result Contract]
```

### Tải cấu hình Nginx từ Server thông qua SSH (NginxFetcher)

Sử dụng công cụ `core/scannerEng/fetcher.py` để kết nối SSH và tải toàn bộ cấu hình Nginx từ server về máy phân tích thông qua CLI.

```bash
# Tải cấu hình từ Nginx VPS 1–5 (Port 2221)
python core/scannerEng/fetcher.py -P 2221

# Tải cấu hình từ Nginx VPS 6–10 (Port 2222)
python core/scannerEng/fetcher.py -P 2222
```

Các tham số được hỗ trợ:

| Tham số            | Mô tả                                              | Mặc định                  |
| ------------------ | --------------------------------------------------- | ------------------------- |
| `-H`, `--host`     | IP của Server                                       | `127.0.0.1`               |
| `-P`, `--port`     | Port SSH của Server **(Bắt buộc)**                  | —                         |
| `-u`, `--user`     | Username SSH                                        | `root`                    |
| `-p`, `--password` | Password SSH                                        | `root`                    |
| `-o`, `--output`   | Thư mục lưu cấu hình giải nén                      | `./tmp/nginx_raw_<port>`  |

---

### Phân tích cấu hình Nginx sang JSON AST (NginxParser)

Sử dụng module `core/scannerEng/parser.py` để tự động hóa việc phân tích cấu hình Nginx (đã được tải về bởi `fetcher.py`) thành định dạng JSON AST. Module này tích hợp sẵn khả năng **chuẩn hóa (normalize)** các đường dẫn `include` tuyệt đối thành đường dẫn tương đối, đảm bảo `crossplane` có thể truy vết và phân tích toàn bộ các file tham chiếu.

```bash
# Phân tích cấu hình từ Nginx VPS 1–5 (Port 2221)
python core/scannerEng/parser.py -P 2221

# Phân tích cấu hình từ Nginx VPS 6–10 (Port 2222)
python core/scannerEng/parser.py -P 2222
```

| Tham số         | Mô tả                                                      | Mặc định                             |
| --------------- | ----------------------------------------------------------- | ------------------------------------ |
| `-P`, `--port`  | Port của Nginx Server đã được fetch **(Bắt buộc)**          | —                                    |
| `-o`, `--output`| Đường dẫn file JSON đầu ra                                 | `contracts/config_ast_<port>.json`   |

**Luồng hoạt động của Parser:**

1. **Xác định nguồn:** Tự động tìm thư mục cấu hình tại `./tmp/nginx_raw_<port>`.
2. **Tiền xử lý:** Quét và chuẩn hóa các chỉ thị `include` bằng Regex để tránh lỗi "No such file or directory".
3. **Trích xuất AST:** Sử dụng thư viện `crossplane` để chuyển đổi sang định dạng JSON.
4. **Xuất kết quả:** Lưu Data Contract vào thư mục `contracts/` phục vụ cho bước quét bảo mật tiếp theo.

---

### Quét Bảo Mật và Đánh Giá (Core Scanner)

Sử dụng module `core/scannerEng/scanner.py` là entry point để phân tích AST JSON dựa trên các quy tắc CIS (đã được định nghĩa trong `recommendations/`), tổng hợp vi phạm và tạo ra **Scan Result Contract**.

```bash
# Quét bảo mật cho VPS 1–5 (Port 2221)
python -m core.scannerEng.scanner --ssh-port 2221

# Quét bảo mật cho VPS 6–10 (Port 2222)
python -m core.scannerEng.scanner --ssh-port 2222
```

**Các tham số CLI:**

| Tham số          | Mô tả                                                        | Mặc định                               |
| ---------------- | ------------------------------------------------------------- | -------------------------------------- |
| `--input`, `-i`  | Path to crossplane parser output JSON                         | `contracts/parser_output_<port>.json`  |
| `--output`, `-o` | Path to write scan result JSON                                | `contracts/scan_result_<port>.json`    |
| `--server-ip`    | IP address of the target Nginx server (metadata only)         | `0.0.0.0`                              |
| `--ssh-port`     | SSH port of the target server                                 | `22`                                   |
| `--ssh-user`     | SSH username                                                  | `root`                                 |
| `--ssh-pass`     | SSH password (optional)                                       | —                                      |
| `--ssh-key`      | Path to SSH private key (optional)                            | —                                      |

**Output mẫu:**

```
[Scanner] 🔍 Chi tiết kết quả kiểm tra (Detailed Findings):
  ❌ 2.4.1 - Ensure NGINX only listens for network connections on authorized ports
  ❌ 2.4.2 - Ensure requests for unknown host names are rejected
  ❌ 2.5.1 - Ensure server_tokens directive is set to off
  ❌ 2.5.2 - Ensure default error and index.html pages do not reference NGINX
  ❌ 2.5.3 - Ensure hidden file serving is disabled
  ✅ 3.1 - Ensure detailed logging is enabled
  ✅ 3.2 - Ensure access logging is enabled
  ✅ 3.3 - Ensure error logging is enabled and set to the info logging level
  ✅ 3.4 - Ensure proxies pass source IP information
  ❌ 4.1.1 - Ensure HTTP is redirected to HTTPS

[Scanner] 📊 Compliance Score: 40%
[Scanner] 📋 Total: 10 | ✅ Pass: 4 | ❌ Fail: 6
```

---

## 🔧 Remediation Engine (`core/remedyEng/`)

### Kiến trúc Interactive Diff Review

Remediation Engine sử dụng mô hình **Interactive Remediation** với các thành phần chính:

| Thành phần            | File                 | Vai trò                                                                                   |
| --------------------- | -------------------- | ----------------------------------------------------------------------------------------- |
| **BaseRemedy**        | `base_remedy.py`     | Base class: file-grouped AST handling, `remediate()`, `build_file_diff_payload()`          |
| **Remediator**        | `remediator.py`      | Orchestrator: registry of 10 remedies, user interaction flow, merge approved changes       |
| **TerminalUI**        | `terminal_ui.py`     | Singleton CLI UI: prompts, diff display, user decisions, input collection                  |
| **ASTEditor**         | `ast_editor.py`      | AST utilities: navigate/modify by context path, render config text, normalize paths        |
| **DiffGenerator**     | `diff_generator.py`  | Unified diff generation (config text + AST JSON fallback)                                  |
| **Remediate Classes** | `recommendations/`   | Mỗi file = 1 class kế thừa `BaseRemedy` với logic `remediate()` riêng                      |

**Remediation Registry** (trong `remediator.py`):

```python
REMEDIATION_REGISTRY: Dict[RecomID, Type[BaseRemedy]] = {
    RecomID.CIS_2_4_1: Remediate241,
    RecomID.CIS_2_4_2: Remediate242,
    RecomID.CIS_2_5_1: Remediate251,
    RecomID.CIS_2_5_2: Remediate252,
    RecomID.CIS_2_5_3: Remediate253,
    RecomID.CIS_3_1:   Remediate31,
    RecomID.CIS_3_2:   Remediate32,
    RecomID.CIS_3_3:   Remediate33,
    RecomID.CIS_3_4:   Remediate34,
    RecomID.CIS_4_1_1: Remediate411,
}
```

**Luồng hoạt động Interactive:**

```
Remediator.apply_remediations()
    │
    ▼  Với mỗi Remediate class trong REMEDIATION_REGISTRY:
    │
    ├── 1. TerminalUI.display_remedy_info()     → Hiển thị CIS rule info
    ├── 2. TerminalUI.display_remedy_decision()  → User chọn apply? (y/n)
    │   └── Nếu "n" → skip, hiển thị rejected
    │
    ├── 3. TerminalUI.user_input()               → Thu thập input (nếu has_input=True)
    ├── 4. remedy.read_child_scan_result()        → Trích violations theo rule
    ├── 5. remedy.read_child_ast_config()         → Trích AST sections per file
    ├── 6. remedy.remediate()                     → Sửa AST in-memory
    │
    ├── 7. Với mỗi affected file:
    │   ├── remedy.build_file_diff_payload()      → Tạo unified diff
    │   ├── TerminalUI.display_remedy_file_diff() → Hiển thị diff
    │   └── TerminalUI.display_file_diff_decision() → User approve file? (y/n)
    │
    ├── 8. TerminalUI.display_remedy_summary()    → Tổng kết accepted/rejected/unchanged
    └── 9. Remediator.merge_remediation()         → Merge approved changes vào AST tổng

Output: Modified AST (toàn bộ cấu hình đã sửa) → contracts/remediated_output.json
```

### Chạy Remediation Engine (Interactive Mode)

```bash
python -m core.remedyEng.run_remedy
```

Khi chạy, hệ thống sẽ yêu cầu nhập lần lượt:

1. **Đường dẫn parser output JSON** (ví dụ: `contracts/parser_output_2221.json`)
2. **Đường dẫn scan result JSON** (ví dụ: `contracts/scan_result_2221.json`)
3. Với mỗi quy tắc CIS:
   - Xem thông tin chi tiết (description, impact, remediation procedure)
   - **Quyết định trước diff** (`y/n`)
   - Nhập thông tin bổ sung nếu rule yêu cầu (ví dụ: log file path, allowed ports)
   - Xem **Unified Diff** cho từng file bị ảnh hưởng
   - **Quyết định áp dụng** cho từng file (`y/n`)
4. Hiển thị summary cho từng remedy (accepted/rejected/unchanged/fallback)
5. Lưu AST sau remediation vào `contracts/remediated_output.json`

### Viết Remediate Plugin mới

Để thêm một quy tắc CIS mới, tạo file Python trong `core/remedyEng/recommendations/`:

```python
# core/remedyEng/recommendations/remediate_XXX.py
from core.recom_registry import RECOMMENDATION_REGISTRY, RecomID
from core.remedyEng.base_remedy import BaseRemedy
from core.remedyEng.ast_editor import ASTEditor
import copy

class RemediateXXX(BaseRemedy):
    def __init__(self) -> None:
        super().__init__(RECOMMENDATION_REGISTRY[RecomID.CIS_X_X_X])
        self.has_input = False          # Set True nếu cần user input
        self.has_guide_detail = True
        self.remedy_guide_detail = "Ví dụ: config mẫu sau remediation"

    def remediate(self) -> None:
        """
        Apply remediation for this CIS rule.

        Available data:
        - self.child_scan_result: {file_path: [remediations]}
        - self.child_ast_config: {file_path: {parsed: [AST nodes]}}
        - self.user_inputs: List[Any] (if has_input=True)

        Output:
        - self.child_ast_modified: {file_path: {parsed: [modified AST]}}
        """
        self.child_ast_modified = {}

        for file_path, file_data in self.child_ast_config.items():
            parsed = file_data.get("parsed", [])
            parsed_copy = copy.deepcopy(parsed)

            # Apply mutations using ASTEditor...

            self.child_ast_modified[file_path] = {"parsed": parsed_copy}
```

Sau đó đăng ký class mới trong `Remediator.REMEDIATION_REGISTRY` (file `remediator.py`).

### Bảng Remediate Classes đã triển khai

| Rule ID     | File                | Mô tả                                                  | Cần User Input |
| ----------- | ------------------- | ------------------------------------------------------- | -------------- |
| `CIS 2.4.1` | `remediate_241.py` | Xóa listen directive trên port không được phép           | ✅ (allowed ports) |
| `CIS 2.4.2` | `remediate_242.py` | Thêm catch-all default server block                     | ❌             |
| `CIS 2.5.1` | `remediate_251.py` | Đặt `server_tokens off;` trong http block               | ❌             |
| `CIS 2.5.2` | `remediate_252.py` | Thêm `error_page` directives cho custom error pages     | ✅ (paths)     |
| `CIS 2.5.3` | `remediate_253.py` | Thêm `location ~ /\\.` block chặn hidden files          | ❌             |
| `CIS 3.1`   | `remediate_31.py`  | Thêm `log_format` JSON structured logging               | ✅ (format)    |
| `CIS 3.2`   | `remediate_32.py`  | Bật `access_log` với scoped log paths                   | ✅ (log paths) |
| `CIS 3.3`   | `remediate_33.py`  | Đặt `error_log` ở mức `info`                           | ✅ (log path)  |
| `CIS 3.4`   | `remediate_34.py`  | Thêm `proxy_set_header` (X-Forwarded-For, X-Real-IP)   | ❌             |
| `CIS 4.1.1` | `remediate_411.py` | Thêm `return 301 https://` redirect cho HTTP blocks     | ❌             |

---

## 🏗️ Kiến trúc tổng thể

Dự án được thiết kế theo kiến trúc **4 tầng** (chi tiết xem [`general_data_flow.txt`](docs/general_data_flow.txt)):

| Tầng       | Mô tả                   | Thành phần                                                             |
| ---------- | ----------------------- | ---------------------------------------------------------------------- |
| **Tầng 1** | Frontend — Streamlit UI | Dashboard UI (Score, Failed Rules) + Remediation UI (Dry-Run, Approve) |
| **Tầng 2** | Backend API — FastAPI   | Endpoints: `/scan`, `/dry-run`, `/approve`                             |
| **Tầng 3** | Core Engines            | Scanner Engine (`scannerEng/`) + Remediation Engine (`remedyEng/`)     |
| **Tầng 4** | Infrastructure          | SQLite DB + Docker Target Nginx Servers                                |

Luồng dữ liệu Core Engines (chi tiết xem [`backend_data_flow.txt`](docs/backend_data_flow.txt)):

```
Target Server → Fetcher → Parser → CIS Rules Scanner → Scan Result → Remediator → Remediated AST Output
```

---

## 📋 Bảng quy tắc CIS được kiểm tra

| #   | CIS Rule  | Mô tả tóm tắt                                     | Detector | Remediate | Tài liệu chi tiết                                                 |
| --- | --------- | ------------------------------------------------- | -------- | --------- | ----------------------------------------------------------------- |
| 1   | CIS 2.4.1 | Chỉ lắng nghe trên các port được ủy quyền         | ✅       | ✅        | [`first-10-recommendations.md`](docs/first-10-recommendations.md) |
| 2   | CIS 2.4.2 | Từ chối request cho hostname không xác định       | ✅       | ✅        | ↑                                                                 |
| 3   | CIS 2.5.1 | Tắt `server_tokens` (ẩn phiên bản Nginx)          | ✅       | ✅        | ↑                                                                 |
| 4   | CIS 2.5.2 | Error/index page không tham chiếu NGINX           | ✅       | ✅        | ↑                                                                 |
| 5   | CIS 2.5.3 | Vô hiệu hóa serving hidden files                  | ✅       | ✅        | ↑                                                                 |
| 6   | CIS 3.1   | Bật detailed logging (JSON format)                | ✅       | ✅        | ↑                                                                 |
| 7   | CIS 3.2   | Bật access logging                                | ✅       | ✅        | ↑                                                                 |
| 8   | CIS 3.3   | Error logging ở mức `info`                        | ✅       | ✅        | ↑                                                                 |
| 9   | CIS 3.4   | Proxy pass source IP (X-Forwarded-For, X-Real-IP) | ✅       | ✅        | ↑                                                                 |
| 10  | CIS 4.1.1 | Redirect HTTP → HTTPS                             | ✅       | ✅        | ↑                                                                 |

---

## 🧪 Chiến lược Test

### Docker Mock Servers (Integration)

Hai VPS giả lập được thiết kế để mỗi bên vi phạm **đúng 5 rule** và tuân thủ **đúng 5 rule còn lại**, đảm bảo scanner phải phát hiện được cả hai loại trạng thái:

| VPS Container       | Port SSH | Vi phạm             | Tuân thủ            |
| ------------------- | -------- | ------------------- | ------------------- |
| `nginx_one_to_five` | 2221     | Rule 1, 2, 3, 4, 5  | Rule 6, 7, 8, 9, 10 |
| `nginx_six_to_then` | 2222     | Rule 6, 7, 8, 9, 10 | Rule 1, 2, 3, 4, 5  |

### Unit Tests (pytest)

Bộ unit test sử dụng `pytest`, đặt trong `tests/unit/scannerEng/`. Mỗi test file kiểm tra:

- **Metadata sanity:** ID, title, required attributes
- **`evaluate()` tests (isolated):** Compliant cases (return `None`) và non-compliant cases (return violation dict)
- **`scan()` tests (full pipeline):** Synthetic parser_output → `BaseRecom.scan()` → `_traverse_ast()` → `evaluate()` → verify findings

**Chạy toàn bộ test:**

```bash
pytest tests/ -v
```

**Chạy test theo module:**

```bash
pytest tests/unit/scannerEng/test_detector_31.py -v
```

| Test File                  | CIS Rule | Số Test Cases |
| -------------------------- | -------- | ------------- |
| `test_detector_241.py`     | 2.4.1    | ~15+          |
| `test_detector_251.py`     | 2.5.1    | ~10+          |
| `test_detector_31.py`      | 3.1      | ~12+          |
| `test_detector_32.py`      | 3.2      | ~10+          |
| `test_detector_33.py`      | 3.3      | ~10+          |

---

## 📚 Tài liệu tham khảo

| Tài liệu                                                               | Mô tả                                                |
| ---------------------------------------------------------------------- | ---------------------------------------------------- |
| [`docs/first-10-recommendations.md`](docs/first-10-recommendations.md) | Chi tiết 10 quy tắc CIS (Audit, Remediation, Impact) |
| [`docs/Impacts.md`](docs/Impacts.md)                                   | Phân tích tác động khi áp dụng từng quy tắc          |
| [`docs/Rationales.md`](docs/Rationales.md)                             | Cơ sở lý luận khoa học cho việc chọn các quy tắc     |
| [`docs/backend_data_flow.txt`](docs/backend_data_flow.txt)             | Sơ đồ luồng dữ liệu Core Engines                     |
| [`docs/general_data_flow.txt`](docs/general_data_flow.txt)             | Sơ đồ kiến trúc tổng thể 4 tầng                      |

---
