# SecRemedy: Nginx Configuration Security Assessment & Auto-Remediation

## Tổng quan dự án (Overview)

**SecRemedy** là một ứng dụng DevSecOps được thiết kế để tự động hóa quá trình đánh giá (assessment) và khắc phục (remediation) cấu hình máy chủ Nginx, tuân thủ theo tiêu chuẩn **CIS Nginx Benchmarks**.

### Bản chất của CIS Nginx Benchmark: Hardening vs Sửa lỗi

- **Mục tiêu chính:** SecRemedy tập trung vào việc **thắt chặt bảo mật (Hardening)** hệ thống dựa trên tập hợp các khuyến nghị "Best Practice", chứ không đơn thuần là sửa lỗi cú pháp (config bug fixing).
- Một máy chủ Nginx vẫn có thể chạy bình thường ngay cả khi không tuân thủ đầy đủ các khuyến nghị này, nhưng sẽ tồn tại các rủi ro lớn về mặt an ninh thông tin.
- Việc sử dụng thuật ngữ **"Khuyến nghị" (Recommendation)** thay vì "Yêu cầu" (Requirement) hay "Luật" (Rule) phản ánh đúng tính chất linh hoạt của Hardening: hệ thống khuyến khích người dùng áp dụng, nhưng cho phép tùy biến dựa trên nhu cầu nghiệp vụ thực tế.

Mục tiêu cốt lõi của SecRemedy là cung cấp một quy trình **"Safe Auto-Remediation"**, cho phép áp dụng các biện pháp Hardening hiệu quả mà vẫn đảm bảo tính an toàn tuyệt đối, tránh gián đoạn dịch vụ (zero-downtime) nhờ cơ chế kiểm tra cú pháp Nginx tự động trước khi ghi đè cấu hình.

## Tính năng cốt lõi (Key Features)

SecRemedy được thiết kế với hai engine độc lập, hoạt động tuần tự và phối hợp qua một **JSON Contract** tiêu chuẩn.

### 1. Trình Đánh giá Bảo mật (Scanner Engine)

- **Thu thập tự động (SSH Fetcher):** Tự động kết nối tới máy chủ mục tiêu qua SSH (`paramiko`), đóng gói và tải về toàn bộ thư mục cấu hình Nginx (thường là `/etc/nginx`) để phân tích ngoại tuyến, đảm bảo an toàn tuyệt đối cho server thật.
- **Phân tích cấu trúc đệ quy (Crossplane Parser):** Sử dụng thư viện `crossplane` để chuyển đổi toàn bộ các tệp cấu hình Nginx (kể cả các tệp lồng nhau qua chỉ thị `include`) thành cây cú pháp trừu tượng (Abstract Syntax Tree - AST) dạng JSON.
- **Phát hiện lỗ hổng (CIS Detectors):** Kế thừa từ class `BaseRecom`, các Detector quét đệ quy qua cây AST (bao gồm các khối `http`, `server`, và `location`) để kiểm tra tính tuân thủ với chuẩn **CIS Nginx Benchmark**. Nguyên lý chung:
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

## Cấu trúc Thư mục (Directory Structure)

```text
SecRemedy/
├── core/                       # Chứa mã nguồn chính của các engines
│   ├── recom_registry.py       # Nơi khai báo và lưu trữ metadata của các khuyến nghị CIS
│   ├── scannerEng/             # Engine quét và phân tích cấu hình Nginx
│   │   ├── fetcher.py          # Script tải thư mục cấu hình Nginx qua SSH
│   │   ├── parser.py           # Script chuyển đổi file Nginx (.conf) sang JSON AST
│   │   ├── scanner.py          # Điều phối quá trình quét (chạy các Detectors)
│   │   ├── base_recom.py       # Class gốc để định nghĩa cấu trúc của một Detector
│   │   └── recommendations/    # Chứa các file `detector_*.py` phát hiện lỗ hổng
│   └── remedyEng/              # Engine sinh bản vá và áp dụng cấu hình tự động
│       ├── remediator.py       # Điều phối quá trình sửa lỗi (chạy các Remedies)
│       ├── run_remedy.py       # Script thực thi chính và quản lý vòng lặp Dry-Run
│       ├── ast_editor.py       # Công cụ thao tác, sửa đổi AST trong RAM
│       ├── diff_generator.py   # Trình tạo Unified Diff giữa cấu hình cũ và mới
│       ├── terminal_ui.py      # Quản lý giao diện dòng lệnh TUI tương tác
│       ├── base_remedy.py      # Class gốc định nghĩa cấu trúc của một Remedy
│       └── recommendations/    # Chứa các file `remediate_*.py` sửa lỗi tự động
├── contracts/                  # Thư mục chứa các file JSON giao tiếp giữa hai Engine
│   ├── parser_output_*.json    # Dữ liệu AST gốc sau khi parse
│   └── scan_result_*.json      # Dữ liệu báo cáo lỗi (JSON Contract) sinh ra bởi Scanner
├── docs/                       # Thư mục chứa tài liệu học thuật và phân tích của đồ án
│   ├── architecture/           # Bản vẽ data flow và các báo cáo thiết kế hệ thống
│   ├── recommendations/        # Tài liệu phân tích Rationales & Impacts của CIS
│   └── tests/                  # Kịch bản kiểm thử và các edge cases cho từng khuyến nghị
├── database/                   # Quản lý các module tương tác với SQLite
└── tests/                      # Thư mục chứa Unit tests và Integration tests
    ├── integration/            # Docker Compose test với các container Nginx thực tế
    └── unit/                   # Các bài test chi tiết cho từng logic của dự án
```

## Kiến trúc Hệ thống (Architecture)

- **Backend Engine:** Python.
- **Database:** SQLite (Lưu trữ lịch sử đánh giá, JSON Contract và trạng thái phê duyệt).
- **Thư viện cốt lõi:**
  - `paramiko`: Xử lý giao tiếp SSH để đọc/ghi file và chạy lệnh trên máy chủ từ xa.
  - `crossplane`: Phân tích cú pháp cấu hình Nginx thành định dạng JSON/AST để dễ dàng xử lý.
  - `difflib`: Sinh Code Diff giúp hiển thị những thay đổi một cách trực quan.

## Hướng dẫn Cài đặt (Installation)

### Yêu cầu hệ thống

- **Python:** 3.10 trở lên.
- **Môi trường:** Server test hoặc VPS đang chạy Nginx để công cụ có thể SSH vào thực hiện đánh giá.

### Các bước cài đặt

1. **Clone repository về máy local:**

   ```bash
   git clone <repository_url>
   cd SecRemedy
   ```

2. **Tạo và kích hoạt môi trường ảo (Virtual Environment):**

   ```bash
   python -m venv venv
   source venv/bin/activate
   ```

3. **Cài đặt các thư viện phụ thuộc:**
   ```bash
   pip install -r requirements.txt
   ```

## Hướng dẫn Sử dụng (Usage)

Hiện tại, hệ thống được phân tách thành các module độc lập hoạt động tuần tự và giao tiếp với nhau thông qua **JSON Contract** lưu trong thư mục `contracts/`.

**1. Thu thập cấu hình Nginx từ máy chủ (Fetcher):**
Sử dụng SSH (thông qua `paramiko`) để nén và tải toàn bộ thư mục cấu hình Nginx (mặc định `/etc/nginx`) về máy local (lưu tại `./tmp/nginx_raw_<port>`).

```bash
python -m core.scannerEng.fetcher -H <ip_server> -P <port_ssh> -u <username> -p <password>
# Ví dụ: python -m core.scannerEng.fetcher -H 127.0.0.1 -P 2221 -u root -p root
```

**2. Phân tích cấu trúc đệ quy (Parser):**
Chuyển đổi các tệp cấu hình đã tải về thành định dạng JSON AST bằng `crossplane` để phục vụ cho việc quét lỗi. Kết quả được lưu tại `contracts/parser_output_<port>.json`.

```bash
python -m core.scannerEng.parser -P <port_ssh>
# Ví dụ: python -m core.scannerEng.parser -P 2221
```

**3. Chạy trình đánh giá bảo mật (Scanner Engine):**
Đánh giá JSON AST theo các khuyến nghị CIS Benchmarks để tìm ra các điểm không tuân thủ và xuất ra báo cáo (JSON Contract) tại `contracts/scan_result_<port>.json`.

```bash
python -m core.scannerEng.scanner --ssh-port <port_ssh>
# Ví dụ: python -m core.scannerEng.scanner --ssh-port 2221
```

**4. Chạy trình tự động khắc phục (Remediation Engine):**
Đọc dữ liệu từ bản quét, hiển thị đề xuất thay đổi (Dry-Run / Unified Diff) và tiến hành sửa lỗi tự động nếu được phê duyệt.

```bash
python -m core.remedyEng.run_remedy
```

_(Lưu ý: Đảm bảo máy chủ mục tiêu cho phép kết nối SSH và tài khoản có đủ quyền đọc `/etc/nginx` để Fetcher có thể hoạt động.)_
