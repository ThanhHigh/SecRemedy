# Tài liệu Kiểm thử: Detector 241 (CIS Nginx Benchmark - Recommendation 2.4.1)

## Tổng quan về Recommendation 2.4.1 trong CIS Nginx Benchmark:

Đảm bảo NGINX chỉ lắng nghe các kết nối mạng trên các cổng được ủy quyền. 
NGINX nên được cấu hình để chỉ lắng nghe trên các cổng và giao thức được ủy quyền. Trong khi HTTP/1.1 và HTTP/2 truyền thống sử dụng cổng TCP 80 và 443, HTTP/3 (QUIC) hiện đại sử dụng cổng UDP 443. Việc đảm bảo NGINX chỉ liên kết với các giao diện và cổng được phê duyệt giúp giảm thiểu bề mặt tấn công.

## Tổng quan về Detector 241

### Mục tiêu của Detector 241

Kiểm tra và đảm bảo NGINX chỉ mở các cổng mạng được cho phép (cụ thể danh sách `authorized_ports = [80, 443, 8080, 8443, 9000]`).
- Đầu vào là AST của cấu hình NGINX (JSON) tổng hợp từ nhiều tệp cấu hình sinh ra bởi thư viện Crossplane.
- Đầu ra là danh sách các uncompliances (JSON) chứa chỉ định hành động `delete` đối với các directive `listen` vi phạm để chuyển cho module Auto-Remediation (cấu trúc đầu ra hoàn toàn tương thích và giống hệt định dạng trong `scan_result_2221.json`).

### Cách hoạt động của Detector 241 dựa trên BaseRecom

Detector 241 kế thừa lớp `BaseRecom` và ghi đè hàm `scan()`. Hàm này nhận vào toàn bộ AST (chứa nhiều file cấu hình). Nó duyệt qua cấu trúc JSON, tìm các block `server` và phân tích tham số của các chỉ thị `listen`. Hàm sẽ bóc tách để tìm ra cổng và kiểm tra xem cổng đó có nằm trong danh sách `authorized_ports` hay không. Nếu phát hiện cổng không hợp lệ, một đối tượng `remediation` với hành động `delete` (nhằm xoá dòng lệnh `listen` vi phạm) và có `exact_path` trỏ tới vị trí của node trên AST sẽ được tạo ra. Cuối cùng, hàm gọi `_group_by_file()` được kế thừa từ `BaseRecom` để tự động gom tất cả các `remediations` có chung đường dẫn `file` thành một danh sách các `uncompliances` hoàn chỉnh và chuẩn hóa.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_241.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra toàn bộ đường ống                     |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector241` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure NGINX only listens for network connections on authorized ports"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`. Đảm bảo cấu trúc đầu ra giống hệt `scan_result_2221.json`.

- **Kiểm tra cấu hình hợp lệ (10 Test Cases):** Đảm bảo không trả về lỗi khi NGINX chỉ sử dụng các cổng trong danh sách `[80, 443, 8080, 8443, 9000]`.
- **Kiểm tra vi phạm cơ bản (10 Test Cases):** Bắt lỗi chính xác khi cấu hình sử dụng các cổng trái phép (ví dụ: 21, 22, 8000). Đảm bảo tạo ra đối tượng remediation với `action: delete` và định tuyến AST bằng `exact_path`.
- **Kiểm tra tham số listen phức tạp (12 Test Cases):** Đảm bảo logic bóc tách số cổng vẫn chính xác khi gặp cú pháp phức tạp như IP (vd: `127.0.0.1:8080`, `[::]:80`) hoặc chứa flags đi kèm (vd: `443 ssl http2`, `443 quic reuseport`).
- **Kiểm tra gom nhóm logic `_group_by_file` (10 Test Cases):** Khi đầu vào AST là tổng hợp từ nhiều file cấu hình khác nhau, kiểm tra xem các remediations thuộc cùng một file có được gom nhóm chính xác thông qua hàm trợ giúp `_group_by_file` hay không.