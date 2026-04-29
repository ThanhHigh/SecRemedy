# Tài liệu Kiểm thử: Detector 242 (CIS Nginx Benchmark - Recommendation 2.4.2)

## Tổng quan về Recommendation 2.4.2 trong CIS Nginx Benchmark:

Đảm bảo các yêu cầu đến tên máy chủ không xác định bị từ chối.
NGINX định tuyến yêu cầu dựa trên Host header. Nếu không có block server mặc định (catch-all) để từ chối các host không xác định, máy chủ sẽ phản hồi cho các tên miền bất kỳ trỏ tới IP, dẫn đến nguy cơ rò rỉ ứng dụng nội bộ hoặc tấn công Host Header.

## Tổng quan về Detector 242

### Mục tiêu của Detector 242

Kiểm tra sự tồn tại của khối `server` mặc định (catch-all) từ chối host lạ. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu không tìm thấy cấu hình catch-all hợp lệ, trả về lỗi kèm hành động `add` để Auto-Remediation chèn khối `server` mặc định vào khối `http`.

### Cách hoạt động của Detector 242 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng `traverse_directive` quét các khối `server`. Tìm khối có `listen` chứa tham số `default_server` (hoặc khối `server` đầu tiên). Kiểm tra khối này có chứa `return 444` (hoặc mã 4xx) và `ssl_reject_handshake on` (nếu có `ssl`). Nếu không có khối nào thỏa mãn, ghi nhận vi phạm tại cấp độ `http` của file cấu hình chính (vd: `nginx.conf`) để chèn khối catch-all chuẩn. Dùng `_group_by_file` gộp vi phạm.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_242.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                              |
| :------------------------------------------------------------------- | :--------------------- | :---------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc  |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện thiếu catch-all |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo các yêu cầu đến tên máy chủ không xác định bị từ chối"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

- **Hợp lệ - Có Catch-All đúng chuẩn (Valid Catch-All) - 5 Test Cases:**
  1. Có `listen 80 default_server;` và `return 444;`.
  2. Có `listen 443 ssl default_server;`, `return 444;`, `ssl_reject_handshake on;`.
  3. Có cả IPv4 và IPv6 `default_server` với `return 4xx`.
  4. Có `listen default_server;` trả về `403` hoặc `400`.
  5. Có `listen 80 default_server;` và location `/` chứa `return 444;`.

- **Không hợp lệ - Thiếu Catch-All (Missing Catch-All) - 10 Test Cases:**
  - 6. Không có khối `server` nào.
  - 7. Có `server` nhưng không có `default_server`.
  - 8. Có nhiều `server` nhưng không cái nào làm `default_server`.
  - 9. Có `server` nghe port 80 nhưng không có `default_server`.
  - 10. Cấu hình HTTPS nhưng thiếu khối bắt lỗi HTTPS.
  - 11. Chỉ có `listen default_server` trong block lỗi ngữ pháp.
  - 12. Không có cấu hình Nginx (AST rỗng).
  - 13. Khối `http` rỗng.
  - 14. File cấu hình phụ không có `default_server` và file chính cũng không.
  - 15. Có khối catch-all nhưng bị comment (Crossplane bỏ qua -> Thiếu).

- **Không hợp lệ - Catch-All cấu hình sai (Misconfigured Catch-All) - 10 Test Cases:**
  - 16. Có `default_server` nhưng không có `return 444` hoặc `4xx`.
  - 17. Có `default_server` trả về `200`.
  - 18. Có `default_server` trả về `301` (redirect rủi ro).
  - 19. HTTPS `default_server` thiếu `ssl_reject_handshake on`.
  - 20. HTTPS `default_server` có `ssl_reject_handshake off`.
  - 21. HTTP có `return 444`, nhưng HTTPS `default_server` trả về `200`.
  - 22. Có `return 444` nhưng thiếu `default_server` trong `listen`.
  - 23. Có `server_name _` nhưng không có `return 4xx` chặn lại.
  - 24. Trả về `return 500` (không an toàn bằng 4xx/444).
  - 25. Có `default_server` HTTP3/QUIC thiếu `return 444`.

- **HTTP vs HTTPS vs HTTP3 (Protocols) - 7 Test Cases:**
  - 26. Thiếu block catch-all cho HTTP.
  - 27. Thiếu block catch-all cho HTTPS.
  - 28. Thiếu block catch-all cho QUIC/HTTP3.
  - 29. Hợp lệ: Catch-all phủ sóng HTTP, HTTPS, QUIC.
  - 30. Lỗi: Có HTTP catch-all, thiếu HTTPS.
  - 31. Lỗi: Có HTTPS catch-all, thiếu HTTP.
  - 32. Cấu hình HTTPS thiếu `ssl_certificate` trong block catch-all giả (nếu không dùng reject_handshake).

- **Cấu hình đa tệp (Multi-file configurations) - 5 Test Cases:**
  - 33. Catch-all nằm ở `nginx.conf`, các file `conf.d/*.conf` không có -> Hợp lệ.
  - 34. Catch-all nằm ở `conf.d/default.conf`, `nginx.conf` include nó -> Hợp lệ.
  - 35. Không file nào có catch-all -> Báo lỗi tại `nginx.conf` khối `http`.
  - 36. Hai file đều định nghĩa `default_server` (lỗi cấu hình Nginx, nhưng detector xử lý sao? -> Vi phạm hoặc cảnh báo trùng lặp).
  - 37. `nginx.conf` rỗng, chỉ có `conf.d/*.conf` thiếu catch-all -> Báo lỗi vào file `http` chính.

- **Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) - 5 Test Cases:**
  - 38. `return 444` nằm sâu trong `location /` của `default_server` -> Hợp lệ.
  - 39. `return 444` có điều kiện `if` -> Phân tích AST xem có an toàn không (thường CIS khuyên không dùng if).
  - 40. Lỗi cấu trúc AST: Không có khối `http` ở file gốc -> Báo lỗi thiếu `http`.
  - 41. Kiểm tra `exact_path` và `action: add` sinh ra đúng payload json để Auto-Remediate chèn block vào cuối `http`.
  - 42. Đảm bảo payload thêm khối catch-all chuẩn (port 80 & 443 ssl_reject_handshake).
