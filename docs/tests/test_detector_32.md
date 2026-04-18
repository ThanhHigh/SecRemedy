# Tài liệu Kiểm thử: Detector 3.2 (CIS Nginx Benchmark - Recommendation 3.2)

## Tổng quan về Recommendation 3.2 trong CIS Nginx Benchmark:

**3.2 Đảm bảo nhật ký truy cập (access logging) được bật (Thủ công)**

Chỉ thị `access_log` cho phép ghi lại các yêu cầu của máy khách. Mặc dù được bật theo mặc định, NGINX cho phép kiểm soát chi tiết ở cấp độ khối `server` hoặc `location`.

Nhật ký truy cập là bản ghi chính về quá trình sử dụng hệ thống, nêu chi tiết ai đã truy cập những tài nguyên nào. Nếu không có nhật ký truy cập đang hoạt động, người ứng phó sự cố sẽ không thể nhận biết các cuộc tấn công dựa trên web và kiểm toán viên không thể xác minh tính tuân thủ hoặc hoạt động của người dùng. Việc này yêu cầu kiểm tra cấu hình để đảm bảo các chỉ thị `access_log` trỏ tới đường dẫn tệp cục bộ hợp lệ và không có `access_log off;` ở cấp độ toàn cục.

## Tổng quan về Detector 3.2

### Mục tiêu của Detector 3.2

Mục tiêu của Detector 3.2 là phát hiện các trường hợp nhật ký truy cập bị vô hiệu hóa (`access_log off;`), đặc biệt là ở phạm vi toàn cục hoặc không được cấu hình hợp lý để lưu vết.
Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane.
Đầu ra là danh sách các uncompliances (JSON) trỏ tới vị trí dòng lệnh có chứa `access_log off;` để chuyển cho module Auto-Remediation.

### Cách hoạt động của Detector 3.2 dựa trên BaseRecom

Dựa trên `BaseRecom`, Detector 3.2 duyệt qua JSON AST, kiểm tra các khối ngữ cảnh như `http`, `server`, và `location`. Detector này sẽ phân tích giá trị của các chỉ thị `access_log` để tìm ra các khai báo tắt nhật ký truy cập (`off`) hoặc đánh giá sự kế thừa của cấu hình log giữa các khối. Các lỗi phát hiện được sẽ đóng gói thành uncompliance.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_32.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra toàn bộ đường ống đối với `access_log`|

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector32` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"3.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure access logging is enabled"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Nhóm 1: Cấu hình hợp lệ tại khối HTTP (Compliant HTTP Block) (7 Test Cases)**: Các trường hợp `access_log` được khai báo đường dẫn rõ ràng tại khối `http` (ví dụ: `access_log /var/log/nginx/access.log;`, các định dạng log khác nhau, syslog). Không ghi nhận lỗi.
- **Nhóm 2: Cấu hình vi phạm tại khối HTTP (Non-compliant HTTP Block) (7 Test Cases)**: Các trường hợp khai báo `access_log off;` tại khối `http` hoặc thiếu hụt hoàn toàn cấu hình ở mức toàn cục. Ghi nhận lỗi báo về module Auto-Remediation.
- **Nhóm 3: Cấu hình hợp lệ tại khối Server/Location (Compliant Server/Location) (7 Test Cases)**: Các khối `server` hoặc `location` cấu hình `access_log` trỏ tới file cụ thể độc lập, ghi đè an toàn hoặc bổ sung cho cấu hình toàn cục.
- **Nhóm 4: Cấu hình vi phạm tại khối Server/Location (Non-compliant Server/Location) (7 Test Cases)**: Các khối `server` hoặc `location` chứa chỉ thị `access_log off;`, làm tắt nhật ký truy cập trái phép ở cấp cục bộ.
- **Nhóm 5: Sự kế thừa cấu hình (Inheritance Logic) (7 Test Cases)**: Kiểm tra các kịch bản kế thừa phức tạp, ví dụ cấu hình `access_log off;` ở `http` nhưng lại được ghi đè bằng đường dẫn hợp lệ ở `server`, hoặc ngược lại cấu hình global hợp lệ nhưng bị tắt ở cấp `server`/`location`.
- **Nhóm 6: Phân tích đa tệp (Multi-file / Includes Parsing) (7 Test Cases)**: Giả lập các tệp cấu hình phân tán, ví dụ `access_log` cấu hình ở tệp `nginx.conf` chính và các tệp trong `conf.d/`, qua đó đánh giá khả năng dò tìm chính xác vị trí tệp và số dòng của chỉ thị vi phạm từ AST do Crossplane tạo ra.