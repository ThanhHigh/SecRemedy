# Tài liệu Kiểm thử: Detector 241 (CIS Nginx Benchmark - Recommendation 2.4.1)

## Tổng quan về Recommendation 2.4.1 trong CIS Nginx Benchmark:

Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền (Manual). NGINX chỉ nên được cấu hình để lắng nghe trên các cổng và giao thức được phép. Giới hạn cổng lắng nghe giúp giảm thiểu bề mặt tấn công, ngăn chặn các dịch vụ ẩn hoặc không mong muốn bị phơi bày. Các cổng được ủy quyền trong hệ thống này: `80`, `443`, `8080`, `8443`, `9000`.

## Tổng quan về Detector 241

### Mục tiêu của Detector 241

Kiểm tra tất cả các chỉ thị `listen` trong toàn bộ cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện chỉ thị `listen` sử dụng cổng ngoài danh sách cho phép, trả về lỗi kèm hành động `delete` để Auto-Remediation loại bỏ cấu hình trái phép.

### Cách hoạt động của Detector 241 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` tìm tất cả chỉ thị `listen` trong khối `server`. Kiểm tra tham số đầu tiên của `listen` (port hoặc IP:port). Nếu cổng trích xuất không thuộc danh sách `[80, 443, 8080, 8443, 9000]`, ghi nhận vi phạm. Thông tin đường dẫn chính xác (`exact_path`) và file chứa vi phạm được lưu để tạo payload remediation dạng `action: delete`. Dùng `_group_by_file` gộp các vi phạm theo từng file.

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
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện cổng sai       |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

- **Hợp lệ - Cổng tiêu chuẩn (Valid Standard Ports) - 5 Test Cases:**
  1. Chỉ chứa `listen 80;`.
  2. Chỉ chứa `listen 443;`.
  3. Chỉ chứa `listen 8080;`.
  4. Chứa kết hợp `listen 80;` và `listen 443;` trong cùng server block.
  5. Chứa kết hợp `8443` và `9000`.

- **Không hợp lệ - Cổng trái phép (Invalid Unauthorized Ports) - 10 Test Cases:**
  - 6. Lắng nghe cổng lạ `listen 8000;` -> Phải xóa.
  - 7. Lắng nghe cổng lạ `listen 8001;`. 8. Lắng nghe cổng `listen 8444;`. 9. Lắng nghe cổng `listen 21;`. 10. Lắng nghe cổng `listen 22;`. 11. Lắng nghe cổng `listen 80;` và `listen 8081;` -> Chỉ bắt lỗi và xóa dòng `8081`. 12. Cấu hình 3 cổng, 2 sai 1 đúng -> Xóa 2 dòng sai. 13. Lắng nghe cổng `listen 4444;`. 14. Lắng nghe cổng `listen 6379;`. 15. Lắng nghe cổng `listen 27017;`.

- **Xử lý địa chỉ IP và Cổng (IP bindings) - 7 Test Cases:**
  - 16. Hợp lệ: `listen 127.0.0.1:80;`.
  - 17. Hợp lệ: `listen 192.168.1.1:443;`.
  - 18. Hợp lệ: `listen 0.0.0.0:8080;`.
  - 19. Không hợp lệ: `listen 127.0.0.1:8000;`.
  - 20. Không hợp lệ: `listen 10.0.0.1:8081;`.
  - 21. Không hợp lệ: `listen 0.0.0.0:22;`.
  - 22. Không hợp lệ: Chỉ IP không có port `listen 127.0.0.1;` (Mặc định là 80, cần xác minh logic xử lý, hợp lệ).

- **Xử lý địa chỉ IPv6 (IPv6 bindings) - 5 Test Cases:**
  - 23. Hợp lệ: `listen [::]:80;`.
  - 24. Hợp lệ: `listen [::]:443;`.
  - 25. Không hợp lệ: `listen [::]:8444;`.
  - 26. Không hợp lệ: `listen [2001:db8::1]:8002;`.
  - 27. Cả IPv4 và IPv6 hợp lệ: `listen 80; listen [::]:80;`.

- **Tham số đi kèm (Ports with arguments) - 5 Test Cases:**
  - 28. Hợp lệ: `listen 443 ssl http2;`.
  - 29. Hợp lệ: `listen 80 default_server;`.
  - 30. Hợp lệ: `listen 443 quic reuseport;`.
  - 31. Không hợp lệ: `listen 8444 ssl http2;`.
  - 32. Không hợp lệ: `listen [::]:8000 default_server;`.

- **Cấu hình đa tệp (Multi-file configurations) - 5 Test Cases:**
  - 33. File 1 đúng (80), File 2 sai (8000). Trả về lỗi thuộc File 2.
  - 34. File 1 sai (8001), File 2 sai (8002). Trả về 2 file vi phạm.
  - 35. 3 files, mỗi file 1 server block hợp lệ -> Trả về rỗng.
  - 36. 3 files, 1 file có 2 block sai -> Gom đúng `remediations` vào file đó.
  - 37. File `nginx.conf` include các `conf.d/*.conf`, lỗi rải rác -> Gom chính xác theo từng file.

- **Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) - 5 Test Cases:**
  - 38. Nhiều block `server` trong cùng `http` -> Bắt lỗi chính xác từng block.
  - 39. Thiếu chỉ thị `listen` -> Nginx mặc định là 80, hợp lệ.
  - 40. Tham số `listen` chứa chữ (ví dụ unix socket) `listen unix:/var/run/nginx.sock;` -> Bỏ qua hoặc hợp lệ.
  - 41. `exact_path` tính toán đúng với block lồng sâu.
  - 42. `logical_context` chứa đúng `['http', 'server']`.
