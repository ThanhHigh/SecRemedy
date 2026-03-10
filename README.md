# SecRemedy

**SecRemedy** là một công cụ tự động đánh giá bảo mật và khắc phục lỗi cấu hình cho Nginx, dựa trên các tiêu chuẩn **CIS Benchmark**. Dự án sử dụng `crossplane` để phân tích cấu hình Nginx thành định dạng JSON AST (Abstract Syntax Tree), tiến hành quét tự động tìm kiếm các điểm yếu, sinh ra báo cáo và quản lý luồng đề xuất khắc phục vào cơ sở dữ liệu SQLite.

---

## 🚀 Tính năng chính

- **Kiểm tra bảo mật tự động:** Đánh giá cấu hình Nginx dựa trên 5 quy tắc trọng điểm của CIS (Ẩn Server Tokens, thiết lập HSTS, phòng chống Clickjacking, chống MIME Sniffing, giới hạn các giao thức TLS hiện đại).
- **Phân tích cấu hình (AST):** Ứng dụng `crossplane` để chuyển đổi tập tin `nginx.conf` sang định dạng JSON, giúp phân tích cấu trúc cấu hình một cách có hệ thống.
- **Tự động đề xuất khắc phục (Remediation):** Khi tìm thấy các quy tắc vi phạm, hệ thống sinh ra báo cáo dạng hợp đồng dữ liệu (Data Contract) để đề xuất chỉ thị cấu hình chính xác (Ví dụ: `server_tokens off;`), hỗ trợ luồng xét duyệt an toàn trước khi áp dụng.
- **Môi trường giả lập Docker Mock Servers:** Tích hợp sẵn 2 container Nginx (cấu hình yếu kém và cấu hình chuẩn) kèm theo dịch vụ SSH giả lập để dễ dàng cho việc phát triển và kiểm thử tự động.
- **Quản lý dữ liệu tập trung:** Ứng dụng SQLAlchemy kết nối với SQLite (`devsecops_nginx.db`) để lưu trữ dữ liệu vòng đời máy chủ, kết quả quét, các quy tắc bị lỗi và tiến trình khắc phục.

---

## 📁 Cấu trúc dự án

```text
SecRemedy/
├── configs/               # Lưu trữ các file cấu hình Nginx để kiểm thử
│   ├── nginx_bad.conf
│   └── nginx_good.conf
├── contracts/             # Data Contracts kết nối giữa quá trình Quét và Khắc phục
│   ├── scan_result.json
│   ├── config_ast_2221.json
│   └── config_ast_2222.json
├── core/                  # Các module lõi và kịch bản thao tác hệ thống
│   ├── models.py
│   ├── test_db.py
│   ├── fetcher.py
│   └── parser.py
├── Dockerfile             # File build hình ảnh Docker (cài Nginx, cấu hình SSH, giả lập SSL)
├── docker-compose.yml     # Khởi chạy cụm 2 servers Nginx giả lập
├── devsecops_nginx.db     # Cơ sở dữ liệu SQLite (Tự sinh sau khi khởi tạo)
├── cis_rule.md            # Tài liệu 5 quy tắc cấu hình bảo mật chuẩn CIS
└── README.md              # Tổng quan dự án (File này)
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
```

### 2. Khởi tạo Cơ sở dữ liệu

Tiến hành tạo cấu trúc bảng cho SQLite:

```bash
python core/test_db.py
```

_(Hệ thống sẽ tự động khởi tạo file `devsecops_nginx.db` với các bảng dữ liệu `servers`, `scan_results`, `failed_rules`, `remediations`)_

### 3. Thiết lập Môi trường thử nghiệm Docker

Dự án SecRemedy sử dụng Docker để thiết lập môi trường test với 2 container Nginx: một container với cấu hình tốt và một container với cấu hình có vấn đề bảo mật. Yêu cầu hệ thống phải cài đặt sẵn **Docker** và **Docker Compose**.

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

- **Nginx "Bad" Server:** HTTP (Port 8081), HTTPS (Port 8443), SSH (Port 2221)
  ```bash
  ssh root@localhost -p 2221
  ```
- **Nginx "Good" Server:** HTTP (Port 8082), HTTPS (Port 8444), SSH (Port 2222)
  ```bash
  ssh root@localhost -p 2222
  ```

**Xử lý sự cố:**

- **Containers không khởi động:** Chạy `docker compose logs` hoặc `docker compose logs nginx-bad` / `nginx-good` để xem lỗi cụ thể.
- **Port đã được sử dụng:** Nếu port 2221 hoặc 2222 bị xung đột, chỉnh sửa file `docker-compose.yml` để thay đổi port mapping.

### 4. Tạo file JSON chứa AST của nginx.conf bằng Crossplane

Crossplane cho phép phân tích cấu hình Nginx thành định dạng JSON AST. (Crossplane đã được cài đặt ở bước 1).

**Tạo file AST từ cấu hình nginx.conf:**

```bash
crossplane parse configs/nginx_bad.conf --out contracts/config_ast.json
```

### 5. Tải cấu hình Nginx từ Server thông qua SSH (NginxFetcher)

Sử dụng công cụ `core/fetcher.py` để kết nối SSH và tải toàn bộ cấu hình Nginx từ server về máy phân tích thông qua CLI.

Ví dụ tải cấu hình từ Nginx "Bad" Server (Port 2221):

```bash
python core/fetcher.py -P 2221
```

Ví dụ tải cấu hình từ Nginx "Good" Server (Port 2222):

```bash
python core/fetcher.py -P 2222
```

Các tham số được hỗ trợ:

- `-H`, `--host`: IP của Server (Mặc định: `127.0.0.1`)
- `-P`, `--port`: Port SSH của Server (Bắt buộc. VD: 2221, 2222)
- `-u`, `--user`: Username SSH (Mặc định: `root`)
- `-p`, `--password`: Password SSH (Mặc định: `root`)
- `-o`, `--output`: Thư mục lưu cấu hình giải nén (Mặc định: `./tmp/nginx_raw_<port>`)

---

### 6. Phân tích cấu hình Nginx sang JSON AST (NginxParser)

Sử dụng module `core/parser.py` để tự động hóa việc phân tích cấu hình Nginx (đã được tải về bởi `fetcher.py`) thành định dạng JSON AST. Module này tích hợp sẵn khả năng **chuẩn hóa (normalize)** các đường dẫn `include` tuyệt đối (thường gặp như `/etc/nginx/...`) thành đường dẫn tương đối, đảm bảo `crossplane` có thể truy vết và phân tích toàn bộ các file tham chiếu mà không gặp lỗi.

**Ví dụ phân tích cấu hình từ Nginx "Bad" Server (Port 2221):**

```bash
python core/parser.py -P 2221
```

**Ví dụ phân tích cấu hình từ Nginx "Good" Server (Port 2222):**

```bash
python core/parser.py -P 2222
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
