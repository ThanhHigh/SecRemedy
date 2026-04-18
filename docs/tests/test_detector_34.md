# Tài liệu Kiểm thử: Detector 3.4 (CIS Nginx Benchmark - Recommendation 3.4)

## Tổng quan về Recommendation 3.4 trong CIS Nginx Benchmark:

**3.4 Ensure proxies pass source IP information**

Khi NGINX hoạt động như một reverse proxy hoặc load balancer, nó sẽ chấm dứt kết nối từ client và mở một kết nối mới tới upstream application server. Các HTTP header chuẩn như `X-Forwarded-For` và `X-Real-IP` phải được cấu hình rõ ràng để truyền địa chỉ IP gốc của client.

## Tổng quan về Detector 3.4

### Mục tiêu của Detector 3.4

Kiểm tra cấu hình Nginx xem có truyền IP gốc client khi dùng `proxy_pass`.
- Đầu vào: AST của cấu hình NGINX (JSON) từ thư viện Crossplane.
- Đầu ra: Danh sách các uncompliances (JSON) chứa các block thiếu cấu hình `proxy_set_header X-Forwarded-For` và `proxy_set_header X-Real-IP` khi có `proxy_pass`, để chuyển cho module Auto-Remediation.

### Cách hoạt động của Detector 3.4 dựa trên BaseRecom

Quét qua các khối cấu hình (http, server, location). Nếu phát hiện `proxy_pass` trong location, tiến hành kiểm tra xem trong scope đó (hoặc scope kế thừa) có tồn tại khai báo `proxy_set_header X-Forwarded-For` và `proxy_set_header X-Real-IP` hay không. Nếu thiếu một hoặc cả hai, đánh dấu là không tuân thủ.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_34.py):

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

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector34` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"3.4"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure proxies pass source IP information"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Nhóm 1: Không chứa proxy_pass (5 test cases):** Đảm bảo không báo lỗi nếu location/server không sử dụng `proxy_pass`.
- **Nhóm 2: Cấu hình hợp lệ tại Location (10 test cases):** Location chứa `proxy_pass` và cấu hình đầy đủ cả 2 header `X-Forwarded-For` và `X-Real-IP`.
- **Nhóm 3: Thiếu cấu hình Header (12 test cases):** Location chứa `proxy_pass` nhưng thiếu `X-Forwarded-For`, thiếu `X-Real-IP`, hoặc thiếu cả hai.
- **Nhóm 4: Kế thừa từ Scope ngoài (10 test cases):** Cấu hình `proxy_set_header` ở khối `http` hoặc `server` và kiểm tra tính kế thừa hợp lệ vào các khối `location` bên trong. Đảm bảo xử lý đúng khi kế thừa bị ghi đè.
- **Nhóm 5: Cấu hình phức tạp và Nested (5 test cases):** Xử lý nhiều file cấu hình, nhiều server block, và nested location với nhiều `proxy_pass` xen kẽ các block tuân thủ và không tuân thủ.