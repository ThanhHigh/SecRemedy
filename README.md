# SecRemedy: Nginx Configuration Security Assessment & Auto-Remediation

## Tổng quan dự án (Overview)

**SecRemedy** là một ứng dụng DevSecOps được thiết kế để tự động hóa quá trình đánh giá (assessment) và khắc phục (remediation) cấu hình máy chủ Nginx, tuân thủ theo tiêu chuẩn **CIS Nginx Benchmarks**.

### Bản chất của CIS Nginx Benchmark: Hardening vs Sửa lỗi

- **Mục tiêu chính:** SecRemedy tập trung vào việc **thắt chặt bảo mật (Hardening)** hệ thống dựa trên tập hợp các khuyến nghị "Best Practice", chứ không đơn thuần là sửa lỗi cú pháp (config bug fixing).
- Một máy chủ Nginx vẫn có thể chạy bình thường ngay cả khi không tuân thủ đầy đủ các khuyến nghị này, nhưng sẽ tồn tại các rủi ro lớn về mặt an ninh thông tin.
- Việc sử dụng thuật ngữ **"Khuyến nghị" (Recommendation)** thay vì "Yêu cầu" (Requirement) hay "Luật" (Rule) phản ánh đúng tính chất linh hoạt của Hardening: hệ thống khuyến khích người dùng áp dụng, nhưng cho phép tùy biến dựa trên nhu cầu nghiệp vụ thực tế.

Mục tiêu cốt lõi của SecRemedy là cung cấp một quy trình **"Safe Auto-Remediation"**, cho phép áp dụng các biện pháp Hardening hiệu quả mà vẫn đảm bảo tính an toàn tuyệt đối, tránh gián đoạn dịch vụ (zero-downtime) nhờ cơ chế kiểm tra cú pháp Nginx tự động trước khi ghi đè cấu hình.

## Tính năng cốt lõi (Key Features)

SecRemedy được thiết kế với hai engine độc lập, hoạt động tuần tự và phối hợp qua một **JSON Contract** tiêu chuẩn lưu trong thư mục `contracts/`.

### 1. Trình Đánh giá Bảo mật (Scanner Engine)

- **Thu thập tự động (SSH Fetcher):** Tự động kết nối tới máy chủ mục tiêu qua SSH (`paramiko`), đóng gói và tải về toàn bộ thư mục cấu hình Nginx (thường là `/etc/nginx`) để phân tích ngoại tuyến, đảm bảo an toàn tuyệt đối cho server thật. **Danh sách port SSH được đọc động từ `docker-compose.yml`** thay vì hardcode.
- **Phân tích cấu trúc đệ quy (Crossplane Parser):** Sử dụng thư viện `crossplane` để chuyển đổi toàn bộ các tệp cấu hình Nginx (kể cả các tệp lồng nhau qua chỉ thị `include`) thành cây cú pháp trừu tượng (Abstract Syntax Tree - AST) dạng JSON.
- **Phát hiện lỗ hổng (CIS Detectors):** Kế thừa từ class `BaseRecom`, **12 Detector** quét đệ quy qua cây AST (bao gồm các khối `http`, `server`, và `location`) để kiểm tra tính tuân thủ với chuẩn **CIS Nginx Benchmark**. Nguyên lý chung:
  - **Dò tìm:** Mỗi Detector sẽ phân giải các thông số cấu hình cụ thể (ví dụ: bóc tách chính xác số port từ IPv4/IPv6 đối với khuyến nghị 2.4.1, kiểm tra block `server` mặc định cho khuyến nghị 2.4.2, hoặc kiểm tra sự vắng mặt của các directive `server_tokens` hay `error_page` đối với khuyến nghị 2.5.1 và 2.5.2).
  - **Đánh giá kế thừa:** Module tự động giải quyết các logic phân cấp và ghi đè của Nginx (ví dụ: truyền `proxy_set_header` ở cấp độ `http` sẽ được kế thừa xuống `location` trong khuyến nghị 3.4, hay sự vắng mặt của khối chặn truy cập file ẩn `.git` trong khuyến nghị 2.5.3).
  - **Xử lý toàn diện (Full Pipeline):** Các Detector có thể truy vết lỗi không chỉ ở `nginx.conf` mà còn ở sâu trong các file cấu hình lồng nhau (`conf.d/*.conf`).
- **JSON Contract & Điểm tuân thủ:** Xuất ra báo cáo chi tiết chứa điểm số bảo mật (Compliance Score). Quan trọng nhất, với mỗi vi phạm phát hiện được, hệ thống sẽ sinh ra một dữ liệu chuẩn (JSON Contract) chứa thông tin hành động cần sửa (`add`, `modify`, `delete`, `add_block`) cùng với `exact_path` (tọa độ chính xác trên AST), cung cấp tiền đề cho module Auto-Remediation can thiệp an toàn.

### 2. Trình Tự động Khắc phục (Remediation Engine)

- **Tương tác trực quan (Terminal UI):** Giao diện dòng lệnh (TUI) cung cấp thông tin chi tiết về từng lỗi bảo mật (Mô tả, Tác động, Hướng dẫn xử lý) và cho phép người dùng lựa chọn chiến lược khắc phục hoặc nhập các thông số tùy chỉnh (như đường dẫn file log, tên server_name).
- **Chỉnh sửa AST chính xác (AST Editor & Injector):** Dựa trên JSON Contract và cấu hình AST đầu vào, công cụ định vị chính xác vị trí cấu hình vi phạm và thực hiện chỉnh sửa bộ nhớ (in-memory) thông minh: thêm, xóa, hoặc sửa các chỉ thị (directives) mà không làm hỏng cấu trúc file gốc.
- **Xem trước thay đổi (Dry-Run Code Diff):** Trước khi áp dụng thay đổi, hệ thống sử dụng `crossplane` để dịch ngược AST đã sửa thành text cấu hình Nginx mới, sau đó dùng `difflib` sinh ra bản Unified Diff. Người dùng có thể đối chiếu trực quan từng dòng code được thêm (`+`) hay bớt (`-`) so với file gốc.

### 3. Quy trình Khắc phục An toàn Không gián đoạn (Safe Remediation Workflow)

SecRemedy đảm bảo nguyên tắc **Zero-Downtime** thông qua quy trình bảo vệ nghiêm ngặt:

1. **Sinh cấu hình tạm:** Build một file cấu hình duy nhất từ AST đã được phê duyệt.
2. **Kiểm thử cú pháp từ xa:** Thực thi lệnh `nginx -t -c <temp_file>` để kiểm tra tính hợp lệ của cấu hình mới do AI/Tool sinh ra.
3. **Quản lý lịch sử (History & Rollback):** Lưu vết toàn bộ thay đổi. Nếu bước kiểm thử cú pháp thất bại, hệ thống dừng quy trình và cho phép người dùng chọn **Rollback** (hoàn tác một rule vừa áp dụng) hoặc **Reapply** (chỉnh sửa lại thông số) mà không làm ảnh hưởng đến máy chủ Nginx đang chạy.
4. **Áp dụng:** Chỉ khi `nginx -t` trả về "syntax is ok", hệ thống mới tiến hành ghi đè file cấu hình gốc trên máy chủ thật và khởi động lại dịch vụ một cách êm ái.

## Môi trường thử nghiệm Docker (Test Environment)

Dự án sử dụng **3 container Nginx Docker** mô phỏng các kịch bản thực tế khác nhau:

| Container           | SSH Port | HTTP Port | HTTPS Port | Mô tả                           |
| ------------------- | :------: | :-------: | :--------: | ------------------------------- |
| `nginx_one_to_five` |  `2221`  |  `8081`   |   `8443`   | ~4–8 lỗi — cấu hình gần thực tế |
| `nginx_six_to_then` |  `2222`  |  `8082`   |   `8444`   | ~1–3 lỗi — hầu hết đã hardened  |
| `nginx_zero_comply` |  `2223`  |  `8080`   |   `8440`   | 0% tuân thủ — baseline tệ nhất  |

Mỗi container mount một thư mục `nginx/` riêng biệt gồm `nginx.conf` và `conf.d/*.conf`.

### Kết quả scan thực tế (Baseline)

| Container                       | Pass | Fail | Compliance Score |
| ------------------------------- | :--: | :--: | :--------------: |
| `nginx_one_to_five` (port 2221) |  4   |  8   |     **33%**      |
| `nginx_six_to_then` (port 2222) |  5   |  7   |     **42%**      |
| `nginx_zero_comply` (port 2223) |  0   |  12  |      **0%**      |

## Cấu trúc Thư mục (Directory Structure)

```text
SecRemedy/
├── core/                           # Mã nguồn chính của các engines
│   ├── recom_registry.py           # Metadata và registry của các khuyến nghị CIS
│   ├── scannerEng/                 # Engine quét và phân tích cấu hình Nginx
│   │   ├── fetcher.py              # SSH fetcher — tải /etc/nginx qua paramiko
│   │   ├── parser.py               # Crossplane parser — chuyển .conf → JSON AST
│   │   ├── scanner.py              # Điều phối scan — chạy tất cả các Detectors
│   │   ├── base_recom.py           # BaseRecom — class gốc cho mọi Detector
│   │   └── recommendations/        # 12 Detector (detector_241.py … detector_532.py)
│   └── remedyEng/                  # Engine sinh bản vá và áp dụng cấu hình tự động
│       ├── run_remedy.py           # Entry point — điều phối vòng lặp Dry-Run/Apply
│       ├── remediator.py           # Điều phối remedy — chạy tất cả các Remedies
│       ├── ast_editor.py           # AST Editor — thao tác in-memory trên AST
│       ├── diff_generator.py       # Sinh Unified Diff bằng difflib
│       ├── terminal_ui.py          # TUI tương tác — hiển thị diff và nhận approval
│       ├── base_remedy.py          # BaseRemedy — class gốc cho mọi Remedy
│       └── recommendations/        # 11 Remedy (remediate_241.py … remediate_411.py)
├── contracts/                      # JSON giao tiếp giữa hai Engine
│   ├── parser_output_<port>.json   # AST gốc sau khi parse (2221, 2222, 2223)
│   ├── scan_result_<port>.json     # Báo cáo lỗi JSON Contract từ Scanner
│   └── remediated_output*.json     # AST đã vá sau Remediation
├── database/                       # Persistence layer — SQLAlchemy + SQLite
│   ├── models.py                   # ORM models: Server, ScanResult, FailedRule, Remediation
│   └── test_db.py                  # Script kiểm tra khởi tạo DB
├── tests/                          # Kiểm thử
│   ├── integration/                # Docker Compose test environment
│   │   ├── docker-compose.yml      # 3 container Nginx (port 2221/2222/2223)
│   │   ├── Dockerfile              # Nginx + OpenSSH image
│   │   ├── vps-one-to-five/        # Config Nginx ~4–8 lỗi
│   │   ├── vps-six-to-then/        # Config Nginx ~1–3 lỗi
│   │   └── zero-comply/            # Config Nginx 0% tuân thủ
│   └── unit/                       # Unit tests cho từng logic
├── docs/                           # Tài liệu học thuật và phân tích
│   ├── architecture/               # Data flow diagrams và thiết kế hệ thống
│   ├── recommendations/            # Phân tích Rationale & Impact của từng CIS rule
│   └── tests/                      # Kịch bản kiểm thử và edge cases
├── notes/                          # Ghi chú phát triển và brainstorm
├── devsecops_nginx.db              # SQLite database (sinh ra lúc runtime)
└── requirements.txt                # Python dependencies
```

## Kiến trúc Hệ thống (Architecture)

- **Backend Engine:** Python 3.10+
- **Database:** SQLite + SQLAlchemy ORM — lưu lịch sử scan, JSON Contract, trạng thái Remediation (`pending_approval` → `approved` → `applied` / `failed`).
- **Thư viện cốt lõi:**
  - `paramiko 4.x` — SSH để đọc/ghi file và chạy lệnh trên máy chủ từ xa.
  - `crossplane 0.5.x` — Parse cấu hình Nginx thành JSON/AST đệ quy.
  - `difflib` (stdlib) — Sinh Unified Code Diff trực quan.
  - `SQLAlchemy 2.x` — ORM layer cho SQLite.
  - `pytest` + `pytest-cov` — Framework kiểm thử và đo độ phủ.

## Hướng dẫn Cài đặt (Installation)

### Yêu cầu hệ thống

- **Python:** 3.10 trở lên.
- **Docker & Docker Compose:** Để chạy môi trường test 3 container.

### Các bước cài đặt

1. **Clone repository:**

   ```bash
   git clone <repository_url>
   cd SecRemedy
   ```

2. **Tạo và kích hoạt môi trường ảo:**

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Cài đặt dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Khởi động môi trường Docker test:**

   ```bash
   cd tests/integration
   docker compose up -d --build
   cd ../..
   ```

## Hướng dẫn Sử dụng (Usage)

Hệ thống hoạt động theo pipeline 3 bước tuần tự. Mỗi bước giao tiếp với bước tiếp theo qua **JSON Contract** lưu trong `contracts/`.

### Bước 1 — Thu thập cấu hình Nginx từ máy chủ (Fetcher)

Kết nối SSH tới từng container, nén và tải về `/etc/nginx` → lưu vào `./tmp/nginx_raw_<port>/`.

Port SSH được **đọc động từ `docker-compose.yml`** — không hardcode.

```bash
# Fetch tất cả container tự động
python -m core.scannerEng.fetcher -a

# Hoặc fetch một server cụ thể
python -m core.scannerEng.fetcher -H <ip> -P <ssh_port> -u <user> -p <password>
```

### Bước 2 — Phân tích cấu trúc đệ quy (Parser)

Chuyển đổi các file `.conf` đã tải về thành JSON AST bằng `crossplane`. Kết quả lưu tại `contracts/parser_output_<port>.json`.

```bash
# Parse tất cả container
python -m core.scannerEng.parser -a

# Parse một port cụ thể
python -m core.scannerEng.parser -P <ssh_port>
```

### Bước 3 — Chạy trình đánh giá bảo mật (Scanner)

Đánh giá JSON AST theo 12 khuyến nghị CIS Benchmarks. Xuất báo cáo tại `contracts/scan_result_<port>.json` kèm Compliance Score.

```bash
# Scan tất cả container
python -m core.scannerEng.scanner -a

# Scan một port cụ thể
python -m core.scannerEng.scanner --ssh-port <ssh_port>
```

### Bước 4 — Chạy trình tự động khắc phục (Remediation Engine)

Đọc `scan_result_*.json`, hiển thị Dry-Run Diff cho từng lỗi, nhận approval của người dùng qua TUI, sau đó áp dụng thay đổi an toàn.

```bash
python -m core.remedyEng.run_remedy
```

> **Lưu ý:** Đảm bảo các container Docker đang chạy trước khi thực hiện bước 1. Tài khoản SSH cần đủ quyền đọc `/etc/nginx`.

## Chạy Unit Tests

Chạy các unit tests độc lập cho remedyEng (không cần Docker/SSH):

```bash
python -m pytest tests/unit/remedyEng -q
```
