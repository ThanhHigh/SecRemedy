# SecRemedy

**SecRemedy** là một công cụ tự động đánh giá bảo mật và khắc phục lỗi cấu hình cho Nginx, dựa trên các tiêu chuẩn **CIS Benchmark v3.0.0**. Dự án sử dụng `crossplane` để phân tích cấu hình Nginx thành định dạng JSON AST (Abstract Syntax Tree), tiến hành quét tự động tìm kiếm các điểm yếu, sinh ra báo cáo và quản lý luồng đề xuất khắc phục an toàn.

---

## 🚀 Tính năng chính

- **Kiểm tra bảo mật tự động:** Đánh giá cấu hình Nginx dựa trên **10 quy tắc trọng điểm** của CIS Benchmark v3.0.0 (xem chi tiết tại [`first-10-recommendations.md`](docs/first-10-recommendations.md)).
- **Phân tích cấu hình (AST):** Ứng dụng `crossplane` để chuyển đổi tập tin `nginx.conf` sang định dạng JSON, giúp phân tích cấu trúc cấu hình một cách có hệ thống.
- **In-Memory Recommendation Registry:** Lưu trữ toàn bộ metadata của 10 quy tắc CIS trong bộ nhớ RAM bằng `dataclass(frozen=True)` và `Enum` ID, cho phép cả Scanner Engine và Remediation Engine truy xuất dữ liệu với độ phức tạp O(1).
- **Scanner Engine (Detector Pattern):** Kiến trúc `BaseRecom` cung cấp thuật toán duyệt đệ quy (Recursive Traversal) cây AST. Mỗi quy tắc CIS được triển khai thành một class Detector riêng biệt kế thừa `BaseRecom` và ghi đè hàm `evaluate()`.
- **Plugin-based Remediation Engine:** Kiến trúc mới sử dụng `BaseRemediation` (ABC) và `RemediationManager` với cơ chế auto-discovery. Mỗi quy tắc CIS là một plugin Python độc lập trong thư mục `rules/`, được tự động phát hiện và đăng ký tại runtime.
- **Tự động đề xuất khắc phục (Remediation):** Khi tìm thấy quy tắc vi phạm, hệ thống sinh ra báo cáo dạng Scan Result Contract, hỗ trợ luồng Dry-Run review (Unified Diff) trước khi áp dụng.
- **Môi trường giả lập Docker Mock Servers:** Tích hợp sẵn 2 container Nginx với các bộ vi phạm CIS khác nhau (Rule 1–5 và Rule 6–10), mount trực tiếp từ thư mục `tests/configs/` để dễ dàng cho việc phát triển và kiểm thử tự động.
- **Quản lý dữ liệu tập trung:** Ứng dụng SQLAlchemy kết nối với SQLite (`devsecops_nginx.db`) để lưu trữ dữ liệu vòng đời máy chủ, kết quả quét, các quy tắc bị lỗi và tiến trình khắc phục.

---

## 📁 Cấu trúc dự án

```text
SecRemedy/
├── core/                                 # Các engine lõi xử lý logic DevSecOps
│   ├── recom_registry.py                 # In-Memory Registry: RecomID (Enum) + Recommendation (frozen dataclass)
│   ├── scannerEng/                       # Scanner Engine — Quét và đánh giá bảo mật
│   │   ├── base_recom.py                 # BaseRecom: Recursive AST traversal + abstract evaluate()
│   │   ├── fetcher.py                    # CLI: Tải cấu hình Nginx từ server qua SSH (Paramiko)
│   │   ├── parser.py                     # CLI: Phân tích nginx.conf sang JSON AST (dùng crossplane)
│   │   ├── scanner.py                    # CLI: Main Scanner Engine quét và đánh giá AST (hỗ trợ tham số dòng lệnh)
│   │   └── recommendations/              # Các class Detector quản lý logic kiểm tra CIS
│   │       ├── detector_241.py           # Detector cho CIS 2.4.1 (Listen port)
│   │       ├── detector_242.py           # Detector cho CIS 2.4.2 (Unknown hostnames)
│   │       └── detector_251.py           # Detector cho CIS 2.5.1 (Server tokens)
│   └── remedyEng/                        # Remediation Engine — Plugin-based auto-remediation
│       ├── base.py                       # BaseRemediation (ABC): check(), fix(), snapshot(), get_diff()
│       ├── manager.py                    # RemediationManager: Auto-discover, orchestrate rule plugins
│       ├── run_remediation.py            # CLI entry-point: --input, --scan-result, --dry-run, --output
│       ├── scan_result_remediation.py    # Processor: Apply scan_result violations to full AST with path normalization
│       ├── paths.py                      # Khai báo đường dẫn gốc dùng chung cho remedy engine
│       ├── rules_list.txt                # Danh sách các rule plugins có sẵn
│       └── rules/                        # Thư mục chứa các plugin remediation (auto-discovered)
│           ├── __init__.py
│           └── cis_2_1_1.py              # Plugin: CIS 2.1.1 — Ensure server_tokens is off
├── database/                             # Tầng persistence — ORM và script khởi tạo DB
│   ├── models.py                         # Định nghĩa ORM (SQLAlchemy): Server, ScanResult, FailedRule, Remediation
│   └── test_db.py                        # Script khởi tạo và seed mock data vào SQLite
├── contracts/                            # Data Contracts kết nối giữa quá trình Quét và Khắc phục
│   ├── scan_result.json                  # Scan Result Contract (output của scanner → input cho remediation)
│   ├── parser_output_2221.json           # Parser output JSON (crossplane AST) từ VPS 1–5 (port 2221)
│   ├── parser_output_2222.json           # Parser output JSON (crossplane AST) từ VPS 6–10 (port 2222)
│   └── config_ast_2221_preview.json      # Preview AST sau khi remediation (dry-run output)
├── docs/                                 # Tài liệu kỹ thuật và nghiên cứu học thuật
│   ├── first-10-recommendations.md       # 10 quy tắc CIS Benchmark chi tiết (Audit, Remediation, ...)
│   ├── Impacts.md                        # Phân tích tác động (Impact) của từng quy tắc CIS
│   ├── Rationales.md                     # Lý do áp dụng (Rationale) — cơ sở lý luận cho luận văn
│   ├── NOTES.md                          # Ghi chú nghiên cứu và quyết định thiết kế (academic notes)
│   ├── backend_data_flow.txt             # Sơ đồ luồng dữ liệu Core Engines
│   └── general_data_flow.txt             # Sơ đồ kiến trúc tổng thể 4 tầng (Frontend → Backend → Core → Infra)
├── tests/                                # Bộ cấu hình Nginx giả lập + Docker infrastructure
│   ├── Dockerfile                        # Build image Docker (Nginx 1.28, SSH, SSL giả lập)
│   ├── docker-compose.yml                # Khởi chạy cụm 2 servers Nginx giả lập (port 2221, 2222)
│   └── configs/                          # Các bộ cấu hình Nginx mount vào container
│       ├── vps-one-to-five/              # VPS giả lập: Vi phạm Rule 1–5, tuân thủ Rule 6–10
│       │   ├── nginx.conf
│       │   ├── conf.d/
│       │   │   ├── emarket.me.conf
│       │   │   ├── admin.emarket.me.conf
│       │   │   ├── customer.emarket.me.conf
│       │   │   └── vendor.emarket.me.conf
│       │   ├── mime.types
│       │   ├── fastcgi_params
│       │   └── proxy_params
│       └── vps-six-to-then/              # VPS giả lập: Vi phạm Rule 6–10, tuân thủ Rule 1–5
│           ├── nginx.conf
│           ├── conf.d/
│           │   ├── emarket.me.conf
│           │   ├── admin.emarket.me.conf
│           │   ├── customer.emarket.me.conf
│           │   └── vendor.emarket.me.conf
│           ├── mime.types
│           ├── fastcgi_params
│           └── proxy_params
|
├── requirements.txt                      # Python dependencies (crossplane, paramiko, sqlalchemy, ...)
├── .gitignore                            # Loại trừ: venv/, tmp/, *.db, __pycache__/, backups/, notes/
└── README.md                             # Tổng quan dự án (File này)
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

Dự án SecRemedy sử dụng Docker để thiết lập môi trường test với 2 container Nginx, mỗi container mount cấu hình trực tiếp từ thư mục `tests/configs/`:

| Container           | Mount Source                     | Mô tả                                    |
| ------------------- | -------------------------------- | ---------------------------------------- |
| `nginx_one_to_five` | `tests/configs/vps-one-to-five/` | Vi phạm CIS Rule 1–5, tuân thủ Rule 6–10 |
| `nginx_six_to_then` | `tests/configs/vps-six-to-then/` | Vi phạm CIS Rule 6–10, tuân thủ Rule 1–5 |

Yêu cầu hệ thống phải cài đặt sẵn **Docker** và **Docker Compose**.

**Quản lý containers:**

```bash
# Build và khởi động containers (chạy từ thư mục tests/)
cd tests && docker compose up -d --build

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
- **Port đã được sử dụng:** Nếu port 2221 hoặc 2222 bị xung đột, chỉnh sửa file `tests/docker-compose.yml` để thay đổi port mapping.

---

## 📡 Data Contracts

Data Contracts là giao diện dữ liệu JSON chính thức kết nối giữa Scanner Engine (Thành viên 1) và Remediation Engine (Thành viên 2). Tất cả các file contract được lưu trong thư mục `contracts/`.

### Scan Result Contract (`scan_result.json`)

Đây là output chính của Scanner Engine, chứa kết quả đánh giá bảo mật và danh sách các vi phạm kèm đề xuất khắc phục:

```json
{
  "scan_id": 1,
  "server_ip": "192.168.1.100",
  "compliance_score": 60,
  "created_at": "2026-03-31T15:41:16Z",
  "recommendations": [
    {
      "id": "2.4.1",
      "title": "Ensure NGINX only listens for network connections on authorized ports",
      "description": "...",
      "rationale": "...",
      "impact": "...",
      "uncompliances": [
        {
          "file": "./tmp/nginx_raw_2222/nginx.conf",
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

### 5. Tải cấu hình Nginx từ Server thông qua SSH (NginxFetcher)

Sử dụng công cụ `core/scannerEng/fetcher.py` để kết nối SSH và tải toàn bộ cấu hình Nginx từ server về máy phân tích thông qua CLI.

Ví dụ tải cấu hình từ Nginx VPS 1–5 (Port 2221):

```bash
python core/scannerEng/fetcher.py -P 2221
```

Ví dụ tải cấu hình từ Nginx VPS 6–10 (Port 2222):

```bash
python core/scannerEng/fetcher.py -P 2222
```

Các tham số được hỗ trợ:

- `-H`, `--host`: IP của Server (Mặc định: `127.0.0.1`)
- `-P`, `--port`: Port SSH của Server (Bắt buộc. VD: 2221, 2222)
- `-u`, `--user`: Username SSH (Mặc định: `root`)
- `-p`, `--password`: Password SSH (Mặc định: `root`)
- `-o`, `--output`: Thư mục lưu cấu hình giải nén (Mặc định: `./tmp/nginx_raw_<port>`)

---

### 6. Phân tích cấu hình Nginx sang JSON AST (NginxParser)

Sử dụng module `core/scannerEng/parser.py` để tự động hóa việc phân tích cấu hình Nginx (đã được tải về bởi `fetcher.py`) thành định dạng JSON AST. Module này tích hợp sẵn khả năng **chuẩn hóa (normalize)** các đường dẫn `include` tuyệt đối (thường gặp như `/etc/nginx/...`) thành đường dẫn tương đối, đảm bảo `crossplane` có thể truy vết và phân tích toàn bộ các file tham chiếu mà không gặp lỗi.

**Ví dụ phân tích cấu hình từ Nginx VPS 1–5 (Port 2221):**

```bash
python core/scannerEng/parser.py -P 2221
```

**Ví dụ phân tích cấu hình từ Nginx VPS 6–10 (Port 2222):**

```bash
python core/scannerEng/parser.py -P 2222
```

**Các tham số hỗ trợ:**

- `-P`, `--port`: Port của Nginx Server đã được fetch (Bắt buộc. VD: 2221, 2222).
- `-o`, `--output`: Đường dẫn file JSON đầu ra (Mặc định: `contracts/config_ast_<port>.json`).

**Luồng hoạt động của Parser:**

1. **Xác định nguồn:** Tự động tìm thư mục cấu hình tại `./tmp/nginx_raw_<port>`.
2. **Tiền xử lý:** Quét và chuẩn hóa các chỉ thị `include` bằng Regex để tránh lỗi "No such file or directory".
3. **Trích xuất AST:** Sử dụng thư viện `crossplane` để chuyển đổi sang định dạng JSON.
4. **Xuất kết quả:** Lưu Data Contract vào thư mục `contracts/` phục vụ cho bước quét bảo mật tiếp theo.

---

### 7. Quét Bảo Mật và Đánh Giá (Core Scanner)

Sử dụng module `core/scannerEng/scanner.py` là entry point để phân tích AST JSON dựa trên các quy tắc CIS (đã được định nghĩa trong `recommendations/`), tổng hợp vi phạm và tạo ra **Scan Result Contract**.

**Ví dụ chạy quét bảo mật cho Port 2221:**

```bash
python core/scannerEng/scanner.py --port 2221
```

**Các tham số:**

---

## 🔧 Remediation Engine (`core/remedyEng/`)

### Kiến trúc Plugin-based (Mới)

Remediation Engine đã được refactor sang kiến trúc **Plugin-based Strategy Pattern** với cơ chế auto-discovery:

| Thành phần                | File                         | Vai trò                                                                         |
| ------------------------- | ---------------------------- | ------------------------------------------------------------------------------- |
| **BaseRemediation (ABC)** | `base.py`                    | Abstract base: `check()`, `fix()`, `snapshot()`, `get_diff()`                   |
| **RemediationManager**    | `manager.py`                 | Auto-discover plugins trong `rules/`, orchestrate thứ tự thực thi               |
| **Scan Result Processor** | `scan_result_remediation.py` | Xử lý Scan Result Contract: normalize paths, apply remediation, output full AST |
| **CLI Entry-point**       | `run_remediation.py`         | CLI wrapper: `--input`, `--scan-result`, `--dry-run`, `--output`                |
| **Rule Plugins**          | `rules/*.py`                 | Mỗi file = 1 class kế thừa `BaseRemediation` với `rule_id` duy nhất             |

**Luồng hoạt động Plugin-based:**

```
RemediationManager.__init__()
    │
    ▼  discover_rules()  → Auto-scan rules/*.py → Đăng ký class vào _registry
    │
    ▼  manager.run(config_json, target_violations, dry_run=True)
    │
    ├── Với mỗi rule_id trong target_violations:
    │   ├── rule.check(config) → Kiểm tra vi phạm còn tồn tại?
    │   ├── rule.fix(config)   → Sửa config in-memory
    │   └── rule.snapshot()    → Lưu trạng thái before/after
    │
    ▼  Trả về { dry_run, preview_config, applied_rules, skipped_rules, diffs }
```

### Chạy Remediation qua CLI (Plugin-based)

```bash
# Dry-run (preview changes from scan_result, không ghi file thật)
python core/remedyEng/run_remediation.py \
  --input contracts/parser_output_2221.json \
  --scan-result contracts/scan_result.json \
  --dry-run

# Apply (ghi file output)
python core/remedyEng/run_remediation.py \
  --input contracts/parser_output_2221.json \
  --scan-result contracts/scan_result.json \
  --output contracts/config_ast_2221_remediated.json
```

**Tham số CLI của `run_remediation.py`:**

| Tham số         | Bắt buộc | Mô tả                                                         |
| --------------- | -------- | ------------------------------------------------------------- |
| `--input`       | ✅       | Đường dẫn file JSON AST (crossplane parsed result)            |
| `--scan-result` | ✅       | Đường dẫn file Scan Result Contract (từ Scanner Engine)       |
| `--dry-run`     | ❌       | Preview changes mà không ghi file output                      |
| `--output`      | ❌       | Đường dẫn file JSON output (mặc định: `<input>_preview.json`) |

**Luồng xử lý Scan Result:**

1. **Load Full AST**: Đọc toàn bộ cấu trúc JSON từ parser_output (giữ nguyên wrapper `status`, `errors`, tất cả configs)
2. **Load Scan Result**: Đọc kết quả quét (recommendations, uncompliances, violations)
3. **Normalize Paths**: Chuẩn hóa đường dẫn file để đảm bảo matching chính xác giữa parser_output và scan_result
4. **Validate Config Files**: Kiểm tra loại file (`.conf`, `.config`, v.v.)
5. **Apply Remediations**: Với mỗi file có issue:
   - Gọi `manager.run_from_scan_result()` để áp dụng các remediation cần thiết
   - Cập nhật config trong AST output
   - Với file không có issue: Giữ nguyên config gốc
6. **Output Full AST**: Xuất AST hoàn chỉnh với tất cả configs (không chỉ config[0])

### Viết Rule Plugin mới

Để thêm một quy tắc CIS mới, tạo file Python trong `core/remedyEng/rules/`:

```python
# core/remedyEng/rules/cis_X_X_X.py
from core.remedyEng.base import BaseRemediation

class MyNewRule(BaseRemediation):
    rule_id = "CIS-X.X.X"
    description = "Mô tả quy tắc"

    def check(self, config_json):
        """Trả về True nếu vi phạm còn tồn tại."""
        # Logic kiểm tra...
        return True

    def fix(self, config_json):
        """Trả về config đã sửa."""
        # Logic sửa lỗi...
        return config_json
```

`RemediationManager` sẽ **tự động** phát hiện và đăng ký class này khi khởi tạo.

### Rule Plugin đã triển khai

| Rule ID     | File           | Mô tả                                            |
| ----------- | -------------- | ------------------------------------------------ |
| `CIS-2.1.1` | `cis_2_1_1.py` | Ensure `server_tokens` directive is set to `off` |

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
Target Server → Fetcher → Parser → CIS Rules Scanner → Scan Result Processor → Remediation Output
```

---

## 📋 Bảng quy tắc CIS được kiểm tra

| #   | CIS Rule  | Mô tả tóm tắt                                     | Tài liệu chi tiết                                                 |
| --- | --------- | ------------------------------------------------- | ----------------------------------------------------------------- |
| 1   | CIS 2.4.1 | Chỉ lắng nghe trên các port được ủy quyền         | [`first-10-recommendations.md`](docs/first-10-recommendations.md) |
| 2   | CIS 2.4.2 | Từ chối request cho hostname không xác định       | ↑                                                                 |
| 3   | CIS 2.5.1 | Tắt `server_tokens` (ẩn phiên bản Nginx)          | ↑                                                                 |
| 4   | CIS 2.5.2 | Error/index page không tham chiếu NGINX           | ↑                                                                 |
| 5   | CIS 2.5.3 | Vô hiệu hóa serving hidden files                  | ↑                                                                 |
| 6   | CIS 3.1   | Bật detailed logging (JSON format)                | ↑                                                                 |
| 7   | CIS 3.2   | Bật access logging                                | ↑                                                                 |
| 8   | CIS 3.3   | Error logging ở mức `info`                        | ↑                                                                 |
| 9   | CIS 3.4   | Proxy pass source IP (X-Forwarded-For, X-Real-IP) | ↑                                                                 |
| 10  | CIS 4.1.1 | Redirect HTTP → HTTPS                             | ↑                                                                 |

---

## 🧪 Chiến lược Test

Hai VPS giả lập được thiết kế để mỗi bên vi phạm **đúng 5 rule** và tuân thủ **đúng 5 rule còn lại**, đảm bảo scanner phải phát hiện được cả hai loại trạng thái:

| VPS Container       | Port SSH | Vi phạm             | Tuân thủ            |
| ------------------- | -------- | ------------------- | ------------------- |
| `nginx_one_to_five` | 2221     | Rule 1, 2, 3, 4, 5  | Rule 6, 7, 8, 9, 10 |
| `nginx_six_to_then` | 2222     | Rule 6, 7, 8, 9, 10 | Rule 1, 2, 3, 4, 5  |

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
