# Tài liệu Kiểm thử: Detector 242 (CIS Nginx Benchmark - Recommendation 2.4.2)

## Tổng quan về Recommendation 2.4.2 trong CIS Nginx Benchmark:

Đảm bảo các yêu cầu (requests) đối với các tên máy chủ (host names) không xác định bị từ chối (Ensure requests for unknown host names are rejected). Nếu không có block `server` mặc định nào xử lý các host không xác định, NGINX sẽ sử dụng block `server` đầu tiên (hoặc block được đánh dấu `default_server`), có thể làm lộ ứng dụng nội bộ hoặc tạo điều kiện cho các cuộc tấn công Host Header. Giải pháp là cấu hình một block server "Catch-All" với chỉ thị `listen ... default_server`, trả về mã lỗi (thường là `return 444;`) và bật `ssl_reject_handshake on;` đối với HTTPS.

## Tổng quan về Detector 242

### Mục tiêu của Detector 242

Mục tiêu của detector 242 là phân tích AST của cấu hình NGINX (JSON) từ thư viện Crossplane để xác định xem cấu hình có một block `server` mặc định từ chối các request không hợp lệ hay không. Đầu ra là danh sách các điểm không tuân thủ (uncompliances) dưới định dạng JSON để chuyển cho module Auto-Remediation (Ví dụ: báo lỗi nếu không tìm thấy `default_server`, hoặc tìm thấy nhưng thiếu `return 4xx/444`, thiếu `ssl_reject_handshake on` đối với HTTPS).

### Cách hoạt động của Detector 242 dựa trên BaseRecom

Detector 242 kế thừa từ class `BaseRecom`, thực hiện duyệt đệ quy qua tất cả các block `server` trong cấu trúc JSON cấu hình Nginx. Nó trích xuất các block có chỉ thị `listen` chứa tham số `default_server`. Sau đó, nó kiểm tra xem bên trong block này có chứa chỉ thị `return` với mã lỗi từ chối hợp lệ (như `444` hoặc `4xx`) hay không. Đối với các block lắng nghe kết nối HTTPS/SSL, nó cũng kiểm tra tính hợp lệ của chỉ thị `ssl_reject_handshake on`. Nếu các điều kiện an toàn không được thỏa mãn, vi phạm sẽ được ghi nhận.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_242.py):

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

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector242` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure requests for unknown host names are rejected"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Kiểm tra sự tồn tại của block `default_server` (10 test cases):** Đảm bảo phát hiện đúng các trường hợp cấu hình hoàn toàn không có block `server` nào; có block `server` nhưng không có tham số `default_server` trong bất kỳ chỉ thị `listen` nào; cấu hình có nhiều file include phức tạp nhưng rải rác không định nghĩa catch-all block.
- **Kiểm tra chỉ thị `return` bên trong `default_server` (12 test cases):** Phát hiện các trường hợp block `default_server` có tồn tại nhưng thiếu chỉ thị `return`; có `return` nhưng mã trả về là 200/301 (không an toàn) thay vì 444 hoặc 4xx; `return` bị cấu hình sai ngữ cảnh (đặt trong block `location` thay vì cấp độ `server`); block `default_server` hoàn toàn chuẩn xác (có `return 444;`).
- **Kiểm tra chỉ thị `ssl_reject_handshake` cho HTTPS/SSL (12 test cases):** Phát hiện các block `default_server` có lắng nghe trên cổng `443 ssl` hoặc tham số `ssl` nhưng thiếu chỉ thị `ssl_reject_handshake on`; trường hợp cấu hình sai là `ssl_reject_handshake off;`; trường hợp block HTTPS/SSL catch-all hoàn toàn chuẩn chỉnh (đáp ứng đủ cả `return 444;` và `ssl_reject_handshake on;`).
- **Kiểm tra các biến thể cấu hình kết hợp và nâng cao (8 test cases):** Phân tích các cấu hình Nginx có sự kết hợp của nhiều block `default_server` (ví dụ một cho IPv4 `listen 80 default_server` và một cho IPv6 `listen [::]:80 default_server`); file có chứa comment hoặc format JSON rỗng/lỗi; đảm bảo detector không raise exception và xử lý gracefully khi thiếu context `http`.