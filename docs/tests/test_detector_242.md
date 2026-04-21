# Tài liệu Kiểm thử: Detector 242 (CIS Nginx Benchmark - Recommendation 2.4.2)

## Tổng quan về Recommendation 2.4.2 trong CIS Nginx Benchmark:

Đảm bảo các yêu cầu tới những tên máy chủ (host names) không xác định bị từ chối. NGINX định tuyến các yêu cầu gửi đến tới máy chủ ảo thích hợp bằng cách đối chiếu tiêu đề Host (HTTP/1.1) hoặc :authority (HTTP/2, HTTP/3) với chỉ thị `server_name` trong cấu hình. Nếu không tìm thấy kết quả khớp chính xác, NGINX sẽ dự phòng (fallback) vào khối máy chủ (server block) đầu tiên được định nghĩa **hoặc** khối được đánh dấu là `default_server`. Nếu không cấu hình khối dự phòng (catch-all) để từ chối các tên máy chủ lạ, máy chủ có thể phản hồi các tên miền bất kỳ trỏ tới địa chỉ IP của bạn, tiềm ẩn rủi ro lộ lọt ứng dụng nội bộ hoặc tạo điều kiện cho các cuộc tấn công Host Header.

## Tổng quan về Detector 242

### Mục tiêu của Detector 242

Kiểm tra toàn bộ cấu hình NGINX để đảm bảo tồn tại ít nhất một khối máy chủ đóng vai trò dự phòng (catch-all) từ chối các kết nối không hợp lệ. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các lỗi vi phạm (uncompliances) dạng JSON để chuyển cho module Auto-Remediation nếu hệ thống thiếu cấu hình từ chối tên máy chủ lạ.

### Cách hoạt động của Detector 242 dựa trên BaseRecom

Detector 242 kế thừa từ `BaseRecom`, sử dụng hàm `traverse_directive` để duyệt qua toàn bộ cây AST cấu hình. Quá trình kiểm tra tập trung vào việc tìm các khối `server` có chứa chỉ thị `listen` đi kèm tham số `default_server`. Nếu tìm thấy khối dự phòng này, Detector sẽ tiếp tục kiểm tra xem bên trong nó có cấu hình từ chối an toàn hay không (như `return 444`, `return 4xx`, hoặc `ssl_reject_handshake on`). Nếu không tồn tại khối dự phòng hợp lệ, một lỗi cấu hình (uncompliance) sẽ được tạo ra và gộp theo file cấu hình gốc.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_242.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case** | **Số lượng Test Case** | **Mục đích chính** |
| :--- | :--- | :--- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) | 3 | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42 | Kiểm tra toàn bộ đường ống |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector242` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure requests for unknown host names are rejected"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Cấu hình an toàn (Compliant) (10 Test Cases):** 
  - Đã có khối server với `listen 80 default_server` và `return 444`.
  - Có khối server với `listen 443 ssl default_server` và `ssl_reject_handshake on`.
  - Khối server mặc định trả về lỗi 403, 404, 400.
  - Hỗ trợ IPv6 `listen [::]:80 default_server`.
  - Hỗ trợ đa giao thức TCP/UDP cho HTTP/3 (`listen 443 quic default_server`).
  - Khối server mặc định chỉ định rõ `server_name _`.

- **Cấu hình vi phạm (Non-Compliant) (15 Test Cases):**
  - Không có bất kỳ khối `server` nào có tham số `default_server`.
  - Có `default_server` nhưng thiếu chỉ thị `return` hoặc `ssl_reject_handshake` để ngắt kết nối.
  - `default_server` trả về mã lỗi 200 (chấp nhận kết nối).
  - Có `ssl_reject_handshake off` khiến chứng chỉ bị lộ.
  - Có `return` nhưng giá trị không phải là 444 hoặc chuỗi lỗi 4xx hợp lệ (ví dụ: `return 301`).

- **Các trường hợp cấu hình phức tạp (Edge Cases & Multiple Files) (17 Test Cases):**
  - Khối server mặc định hợp lệ nằm trong một tệp được `include` (như `conf.d/default.conf`).
  - Nhiều tệp cấu hình, không tệp nào chứa cấu hình `default_server`.
  - Tham số `listen` chứa nhiều tùy chọn phức tạp như `listen 80 default_server proxy_protocol ipv6only=on`.
  - Cấu hình có nhiều `listen` trong cùng một khối `server` (ví dụ cả 80 và 443) và xử lý `return` chính xác.
  - Khối server dự phòng có chứa các directives rác không ảnh hưởng đến đánh giá.
  - Xử lý mảng AST rỗng hoặc cấu hình thiếu khối `http`.
