# SecRemedy

**SecRemedy** là một công cụ tự động đánh giá bảo mật và khắc phục lỗi cấu hình cho Nginx, dựa trên các tiêu chuẩn **CIS Benchmark v3.0.0**. Dự án sử dụng `crossplane` để phân tích cấu hình Nginx thành định dạng JSON AST (Abstract Syntax Tree), tiến hành quét tự động tìm kiếm các điểm yếu, sinh ra báo cáo và quản lý luồng đề xuất khắc phục vào cơ sở dữ liệu SQLite.

---

## 🚀 Tính năng chính

- **Kiểm tra bảo mật tự động:** Đánh giá cấu hình Nginx dựa trên **10 quy tắc trọng điểm** của CIS Benchmark v3.0.0 (xem chi tiết tại [`first-ten-recommendations.md`](first-ten-recommendations.md).
- **Phân tích cấu hình (AST):** Ứng dụng `crossplane` để chuyển đổi tập tin `nginx.conf` sang định dạng JSON, giúp phân tích cấu trúc cấu hình một cách có hệ thống.
- **Tự động đề xuất khắc phục (Remediation):** Khi tìm thấy các quy tắc vi phạm, hệ thống sinh ra báo cáo dạng hợp đồng dữ liệu (Data Contract) để đề xuất chỉ thị cấu hình chính xác (Ví dụ: `server_tokens off;`), hỗ trợ luồng xét duyệt an toàn trước khi áp dụng.
- **Môi trường giả lập Docker Mock Servers:** Tích hợp sẵn 2 container Nginx với các bộ vi phạm CIS khác nhau (Rule 1–5 và Rule 6–10), mount trực tiếp từ thư mục `tests/` để dễ dàng cho việc phát triển và kiểm thử tự động.
- **Quản lý dữ liệu tập trung:** Ứng dụng SQLAlchemy kết nối với SQLite (`devsecops_nginx.db`) để lưu trữ dữ liệu vòng đời máy chủ, kết quả quét, các quy tắc bị lỗi và tiến trình khắc phục.

---

## 📁 Cấu trúc dự án

```text
SecRemedy/
├── core/                             # Các engine lõi xử lý logic DevSecOps
│   ├── scannerEng/                   # Scanner Engine — Quét và đánh giá bảo mật
│   │   ├── models.py                 # Định nghĩa ORM (SQLAlchemy): Server, ScanResult, FailedRule, Remediation
│   │   ├── test_db.py                # Script khởi tạo và kiểm tra cơ sở dữ liệu SQLite
│   │   ├── fetcher.py                # CLI: Tải cấu hình Nginx từ server qua SSH
│   │   └── parser.py                 # CLI: Phân tích nginx.conf sang JSON AST (dùng crossplane)
│   └── remedyEng/                    # Remediation Engine — Inject cấu hình an toàn vào AST
│       ├── backup.py                 # CLI: Backup trước khi sửa file cấu hình của Nginx
│       ├── ast_locator.py            # CLI: Định vị block trong cây AST theo context_path
│       ├── injector.py               # CLI: Inject/cập nhật directive vào AST dựa trên failed_rules
│       ├── builder.py                # CLI: Build ngược từ AST JSON sang nginx config text
│       ├── diff.py                   # CLI: So sánh file nginx gốc và file đã remediate (dry-run review)
│       └── paths.py                  # Khai báo đường dẫn gốc dùng chung cho remedy engine
├── contracts/                        # Data Contracts kết nối giữa quá trình Quét và Khắc phục
│   ├── scan_result.json              # Kết quả quét bảo mật (output của scanner)
│   ├── config_ast_2221.json          # AST JSON của Nginx VPS 1–5 (port 2221)
│   └── config_ast_2222.json          # AST JSON của Nginx VPS 6–10 (port 2222)
├── tests/                            # Bộ cấu hình Nginx giả lập để kiểm thử CIS compliance
│   ├── vps-one-to-five/              # VPS giả lập: Vi phạm Rule 1–5, tuân thủ Rule 6–10
│   │   ├── nginx.conf
│   │   ├── conf.d/
│   │   │   ├── emarket.me.conf
│   │   │   ├── admin.emarket.me.conf
│   │   │   ├── customer.emarket.me.conf
│   │   │   └── vendor.emarket.me.conf
│   │   ├── mime.types
│   │   ├── fastcgi_params
│   │   └── proxy_params
│   └── vps-six-to-then/              # VPS giả lập: Vi phạm Rule 6–10, tuân thủ Rule 1–5
│       ├── nginx.conf
│       ├── conf.d/
│       │   ├── emarket.me.conf
│       │   ├── admin.emarket.me.conf
│       │   ├── customer.emarket.me.conf
│       │   └── vendor.emarket.me.conf
│       ├── mime.types
│       ├── fastcgi_params
│       └── proxy_params
├── tmp/                              # (Tự sinh, gitignored) Dữ liệu tạm trong quá trình xử lý
│   ├── ast_modified/                 # AST JSON sau khi inject remediation
│   │   └── config_ast_<port>_modified.json
│   ├── nginx_raw_<port>/             # VD: nginx_raw_2221/ — toàn bộ /etc/nginx từ server
│   └── nginx_fixed_<port>/           # File nginx.conf text sau khi build lại từ AST
├── Dockerfile                        # Build image Docker (Nginx 1.28, SSH, SSL giả lập)
├── docker-compose.yml                # Khởi chạy cụm 2 servers Nginx giả lập (port 2221, 2222)
├── first-ten-recommendations.md      # 10 quy tắc CIS Benchmark chi tiết (Audit, Remediation, ...)
├── backend_data_flow.txt             # Sơ đồ luồng dữ liệu Core Engines
├── general_data_flow.txt             # Sơ đồ kiến trúc tổng thể 4 tầng (Frontend → Backend → Core → Infra)
├── cis_rule.md                       # Tóm tắt 5 quy tắc bảo mật CIS gốc
├── devsecops_nginx.db                # Cơ sở dữ liệu SQLite (tự sinh, gitignored)
└── README.md                         # Tổng quan dự án (File này)
```

---

## 🛠️ Hướng dẫn cài đặt & Khởi chạy

### 1. Chuẩn bị môi trường Python

Cài đặt các gói thư viện Python cần thiết:

```bash
# Cài đặt crossplane để phân tích cấu hình Nginx
pip install crossplane

# Cài đặt SQLAlchemy để sử dụng cơ sở dữ liệu
pip install sqlalchemy

# Cài đặt Paramiko để SSH/backup cấu hình từ server
pip install paramiko
```

### 2. Khởi tạo Cơ sở dữ liệu

Tiến hành tạo cấu trúc bảng cho SQLite:

```bash
python core/scannerEng/test_db.py
```

_(Hệ thống sẽ tự động khởi tạo file `devsecops_nginx.db` với các bảng dữ liệu `servers`, `scan_results`, `failed_rules`, `remediations`)_

### 3. Thiết lập Môi trường thử nghiệm Docker

Dự án SecRemedy sử dụng Docker để thiết lập môi trường test với 2 container Nginx, mỗi container mount cấu hình trực tiếp từ thư mục `tests/`:

| Container           | Mount Source             | Mô tả                                    |
| ------------------- | ------------------------ | ---------------------------------------- |
| `nginx_one_to_five` | `tests/vps-one-to-five/` | Vi phạm CIS Rule 1–5, tuân thủ Rule 6–10 |
| `nginx_six_to_then` | `tests/vps-six-to-then/` | Vi phạm CIS Rule 6–10, tuân thủ Rule 1–5 |

Yêu cầu hệ thống phải cài đặt sẵn **Docker** và **Docker Compose**.

**Quản lý containers:**

```bash
# Build và khởi động containers
docker compose up -d --build

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
- **Port đã được sử dụng:** Nếu port 2221 hoặc 2222 bị xung đột, chỉnh sửa file `docker-compose.yml` để thay đổi port mapping.

### 4. Tạo file JSON chứa AST của nginx.conf bằng Crossplane

Crossplane cho phép phân tích cấu hình Nginx thành định dạng JSON AST. (Crossplane đã được cài đặt ở bước 1).

**Tạo file AST từ cấu hình nginx.conf:**

```bash
crossplane parse tests/vps-one-to-five/nginx.conf --out contracts/config_ast_manual.json
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

### 7. Inject Khắc phục vào AST (remedyEng)

Module `core/remedyEng/` là **Engine Khắc phục** — nhận vào file AST JSON đã được phân tích và danh sách các quy tắc vi phạm (`failed_rules`), sau đó tự động chèn/cập nhật các directive an toàn vào đúng vị trí trong cây AST.

#### 7.1. Kiến trúc remedyEng

| File             | Vai trò                                                                              |
| ---------------- | ------------------------------------------------------------------------------------ |
| `backup.py`      | Kết nối SSH bằng `paramiko` để backup thư mục cấu hình Nginx trên server/container   |
| `ast_locator.py` | Định vị (locate) các block AST theo `context_path` (VD: `["http", "server"]`)        |
| `injector.py`    | Inject/cập nhật directive an toàn vào block AST, xuất file `_modified.json`          |
| `builder.py`     | Chuyển AST JSON đã chỉnh sửa về lại text cấu hình Nginx bằng `crossplane.build()`    |
| `diff.py`        | So sánh `nginx.conf` gốc và file đã build sau remediate bằng Unified Diff            |
| `paths.py`       | Tính `ROOT_DIR` của project để các module trong `remedyEng` dùng đường dẫn nhất quán |

#### 7.2. Viết `mock_failed_rules` — Định dạng dữ liệu đầu vào

`mock_failed_rules` là một Python list mô phỏng dữ liệu từ cột `FailedRule` trong Database (do bước Scanner quét ra). Mỗi phần tử là một dict với cấu trúc sau:

```python
mock_failed_rules = [
    {
        "rule_id": "CIS_2.1.3",               # ID quy tắc CIS
        "rule_name": "Ensure server_tokens is off",  # Mô tả quy tắc
        "severity": "High",                    # Mức độ: High / Medium / Low
        "target_context": ["http"],            # Đường dẫn block trong AST cần vá
                                               # VD: ["http"] -> block http {}
                                               #     ["http", "server"] -> block server {} bên trong http {}
        "recommended_directive": {
            "directive": "server_tokens",      # Tên directive Nginx cần thêm/ghi đè
            "args": ["off"]                    # Danh sách tham số
        }
    },
    {
        "rule_id": "CIS_5.1.3",
        "rule_name": "Ensure X-Frame-Options header is configured",
        "severity": "Medium",
        "target_context": ["http", "server"],  # Áp dụng cho TẤT CẢ block server trong http
        "recommended_directive": {
            "directive": "add_header",
            "args": ["X-Frame-Options", "SAMEORIGIN"]
            # Chú ý: add_header được xử lý đặc biệt — so khớp theo args[0] (tên header)
            # để tránh tạo nhiều dòng add_header trùng tên
        }
    },
    {
        "rule_id": "CIS_3.1",
        "rule_name": "Ensure outdated SSL protocols are disabled",
        "severity": "Medium",
        "target_context": ["http", "server"],
        "recommended_directive": {
            "directive": "ssl_protocols",
            "args": ["TLSv1.2", "TLSv1.3"]
            # Tool sẽ TỰ ĐỘNG GHI ĐÈ nếu ssl_protocols đã tồn tại với giá trị cũ
        }
    }
]
```

**Quy tắc viết `target_context`:**

| `target_context`                 | Directive được inject vào                          |
| -------------------------------- | -------------------------------------------------- |
| `["http"]`                       | Block `http { }` ở cấp toàn cục                    |
| `["http", "server"]`             | Tất cả các block `server { }` nằm trong `http { }` |
| `["http", "server", "location"]` | Tất cả block `location { }` trong mỗi `server { }` |

**Logic Inject của injector.py:**

- Nếu directive **đã tồn tại** trong block → **Ghi đè** (`args` mới)
- Nếu directive **chưa tồn tại** → **Thêm mới** vào cuối block
- Trường hợp `add_header` → So sánh thêm `args[0]` (tên header) để tránh trùng

#### 7.3. Chạy Injector để sinh Modified AST

> **Yêu cầu:** Đã có file AST JSON tại `contracts/` (sinh ra từ bước 6).
> Nên chạy lệnh từ **project root** (thư mục chứa `README.md`) để các đường dẫn input/output đúng mặc định.

**Bước 1:** Backup file cấu hình Nginx trước khi sửa đổi

```bash
python core/remedyEng/backup.py
```

> `backup.py` hiện dùng cấu hình test cứng (`127.0.0.1:2221`, user/pass `root/root`, source `/etc/nginx`) và tạo bản sao dạng `/etc/nginx_backup_YYYYMMDD_HHMMSS` trên server.

**Bước 2:** Chạy injector với file AST của Nginx VPS 1–5 (port 2221):

```bash
python core/remedyEng/injector.py -i contracts/config_ast_2221.json
```

File đầu ra sẽ được tự động tạo tại:

```
tmp/ast_modified/config_ast_2221_modified.json
```

**Hoặc chỉ định đường dẫn output thủ công:**

```bash
python core/remedyEng/injector.py -i contracts/config_ast_2221.json -o contracts/config_ast_2221_patched.json
```

**Tham số CLI của `injector.py`:**

| Tham số          | Bắt buộc | Mô tả                                                                        |
| ---------------- | -------- | ---------------------------------------------------------------------------- |
| `-i`, `--input`  | ✅       | Đường dẫn file JSON AST gốc (tương đối từ project root)                      |
| `-o`, `--output` | ❌       | Đường dẫn file JSON output. Mặc định: `tmp/ast_modified/<tên>_modified.json` |

**Xem help:**

```bash
python core/remedyEng/injector.py -h
```

#### 7.4. Build lại file nginx.conf từ Modified AST (builder.py)

Sau khi có file AST đã vá, dùng `builder.py` để chuyển về dạng text cấu hình Nginx:

```bash
python core/remedyEng/builder.py \
  -i tmp/ast_modified/config_ast_2221_modified.json \
  -o tmp/nginx_fixed_2221/nginx_fixed.conf
```

Bạn có thể mở file output để review trước khi apply lên server/container.

#### 7.5. Kiểm tra kết quả Modified AST

Sau khi chạy xong, mở file `tmp/ast_modified/config_ast_2221_modified.json` và tìm kiếm các directive đã được vá:

```bash
# Kiểm tra server_tokens đã được thêm vào block http chưa
grep -A1 '"server_tokens"' tmp/ast_modified/config_ast_2221_modified.json

# Kiểm tra X-Frame-Options đã được inject vào các block server chưa
grep -A2 '"X-Frame-Options"' tmp/ast_modified/config_ast_2221_modified.json

# Kiểm tra ssl_protocols đã được ghi đè sang TLSv1.2/TLSv1.3 chưa
grep -A3 '"ssl_protocols"' tmp/ast_modified/config_ast_2221_modified.json
```

#### 7.6. So sánh trước/sau bằng `diff.py` (Dry-run)

Sau khi đã build lại file cấu hình, dùng `diff.py` để kiểm tra chính xác các dòng thay đổi trước khi apply lên server/container:

```bash
python core/remedyEng/diff.py \
    --origin tmp/nginx_raw_2221/nginx.conf \
    --modified tmp/nginx_fixed_2221/nginx_fixed.conf
```

Kết quả trả về là **Unified Diff** (dòng thêm `+`, dòng xóa `-`).

- Nếu có thay đổi: review nội dung rồi mới apply thực tế.
- Nếu không có thay đổi: tool sẽ in `Cấu hình đã an toàn, không có thay đổi nào được đề xuất.`

#### 7.7. Kiểm tra nhanh context AST bằng `ast_locator.py`

`ast_locator.py` hữu ích khi cần debug đường dẫn `target_context` trước khi inject.

```bash
python core/remedyEng/ast_locator.py -i contracts/config_ast_2221.json
```

Hiện file này chủ yếu phục vụ utility/debug nội bộ (đã có sẵn hàm `locate_blocks()` để `injector.py` sử dụng trực tiếp).

#### 7.8. Luồng hoàn chỉnh từ Fetch → Parse → Inject → Build → Diff

```
[Docker Server :2221]
        │
        ▼  python core/scannerEng/fetcher.py -P 2221
[tmp/nginx_raw_2221/]  ← Cấu hình Nginx thô (tải về qua SSH)
        │
        ▼  python core/scannerEng/parser.py -P 2221
[contracts/config_ast_2221.json]  ← AST JSON đầy đủ (crossplane)
        │
        ▼  python core/remedyEng/injector.py -i contracts/config_ast_2221.json
[tmp/ast_modified/config_ast_2221_modified.json]  ← AST đã vá lỗi bảo mật ✅
    │
    ▼  python core/remedyEng/builder.py -i tmp/ast_modified/config_ast_2221_modified.json -o tmp/nginx_fixed_2221/nginx_fixed.conf
[tmp/nginx_fixed_2221/nginx_fixed.conf]  ← File cấu hình Nginx text sau khi remediate ✅
    │
    ▼  python core/remedyEng/diff.py --origin tmp/nginx_raw_2221/nginx.conf --modified tmp/nginx_fixed_2221/nginx_fixed.conf
[Unified Diff Output]  ← So sánh thay đổi trước khi apply ✅
```

---

## 🏗️ Kiến trúc tổng thể

Dự án được thiết kế theo kiến trúc **4 tầng** (chi tiết xem [`general_data_flow.txt`](general_data_flow.txt)):

| Tầng       | Mô tả                   | Thành phần                                                             |
| ---------- | ----------------------- | ---------------------------------------------------------------------- |
| **Tầng 1** | Frontend — Streamlit UI | Dashboard UI (Score, Failed Rules) + Remediation UI (Dry-Run, Approve) |
| **Tầng 2** | Backend API — FastAPI   | Endpoints: `/scan`, `/dry-run`, `/approve`                             |
| **Tầng 3** | Core Engines            | Scanner Engine (`scannerEng/`) + Remediation Engine (`remedyEng/`)     |
| **Tầng 4** | Infrastructure          | SQLite DB + Docker Target Nginx Servers                                |

Luồng dữ liệu Core Engines (chi tiết xem [`backend_data_flow.txt`](backend_data_flow.txt)):

```
Target Server → Fetcher → Parser → CIS Rules Evaluator → Locator & Injector → Builder → Diff Generator
```

---

## 📋 Bảng quy tắc CIS được kiểm tra

| #   | CIS Rule  | Mô tả tóm tắt                                     | Tài liệu chi tiết                                              |
| --- | --------- | ------------------------------------------------- | -------------------------------------------------------------- |
| 1   | CIS 2.4.1 | Chỉ lắng nghe trên các port được ủy quyền         | [`first-ten-recommendations.md`](first-ten-recommendations.md) |
| 2   | CIS 2.4.2 | Từ chối request cho hostname không xác định       | ↑                                                              |
| 3   | CIS 2.5.1 | Tắt `server_tokens` (ẩn phiên bản Nginx)          | ↑                                                              |
| 4   | CIS 2.5.2 | Error/index page không tham chiếu NGINX           | ↑                                                              |
| 5   | CIS 2.5.3 | Vô hiệu hóa serving hidden files                  | ↑                                                              |
| 6   | CIS 3.1   | Bật detailed logging (JSON format)                | ↑                                                              |
| 7   | CIS 3.2   | Bật access logging                                | ↑                                                              |
| 8   | CIS 3.3   | Error logging ở mức `info`                        | ↑                                                              |
| 9   | CIS 3.4   | Proxy pass source IP (X-Forwarded-For, X-Real-IP) | ↑                                                              |
| 10  | CIS 4.1.1 | Redirect HTTP → HTTPS                             | ↑                                                              |

---

## 🧪 Chiến lược Test

Hai VPS giả lập được thiết kế để mỗi bên vi phạm **đúng 5 rule** và tuân thủ **đúng 5 rule còn lại**, đảm bảo scanner phải phát hiện được cả hai loại trạng thái:

| VPS Container       | Port SSH | Vi phạm             | Tuân thủ            |
| ------------------- | -------- | ------------------- | ------------------- |
| `nginx_one_to_five` | 2221     | Rule 1, 2, 3, 4, 5  | Rule 6, 7, 8, 9, 10 |
| `nginx_six_to_then` | 2222     | Rule 6, 7, 8, 9, 10 | Rule 1, 2, 3, 4, 5  |

---
