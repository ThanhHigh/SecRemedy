# Tài liệu Kiểm thử: Detector 411 (CIS Nginx Benchmark - Recommendation 4.1.1)

## Tổng quan về Recommendation 4.1.1 trong CIS Nginx Benchmark:

Đảm bảo HTTP được chuyển hướng sang HTTPS. Các trình duyệt và máy khách thiết lập các kết nối được mã hóa với máy chủ thông qua HTTPS. Các yêu cầu sử dụng HTTP không được mã hóa. Các yêu cầu không mã hóa cần được chuyển hướng để chúng được mã hóa. Bất kỳ cổng HTTP nào đang lắng nghe trên máy chủ web của bạn cũng nên chuyển hướng đến một cấu hình máy chủ sử dụng mã hóa (mặc định cổng HTTP là 80).

## Tổng quan về Detector 411

### Mục tiêu của Detector 411

Kiểm tra tất cả các khối `server` trong cấu hình NGINX xem có cổng HTTP nào đang lắng nghe (ví dụ: cổng 80) mà không có cấu hình chuyển hướng sang HTTPS hay không. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện khối `server` lắng nghe HTTP mà thiếu chỉ thị `return 301 https://...` (hoặc chuyển hướng không hợp lệ), trả về lỗi kèm hành động `add` (hoặc `replace`) để Auto-Remediation tự động khắc phục.

### Cách hoạt động của Detector 411 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` tìm tất cả các khối `server`.

1. Kiểm tra các chỉ thị `listen` bên trong khối `server`. Nếu phát hiện cổng không mã hóa (ví dụ: `80`, `[::]:80`, hoặc `listen` không có `ssl`).
2. Kiểm tra xem khối `server` đó có chứa chỉ thị `return` hoặc `rewrite` thực hiện chuyển hướng sang `https://` hay không.
3. Nếu không có chuyển hướng hoặc chuyển hướng sai (sang `http://` hoặc mã trạng thái không phải 301/302/308), ghi nhận vi phạm với `action: add` (nếu thiếu) hoặc `replace` (nếu sai) để cấu hình lại thành `return 301 https://$host$request_uri;`.
4. Dùng `_group_by_file` gộp các vi phạm theo từng file để Auto-Remediation xử lý hiệu quả.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_411.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và chuyển hướng HTTP/HTTPS  |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector411` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"4.1.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo HTTP được chuyển hướng sang HTTPS"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Hợp lệ - Đã cấu hình chuyển hướng (Valid Configurations) - 5 Test Cases:**
  1. Khối `server` lắng nghe port 80 và có `return 301 https://$host$request_uri;`.
  2. Khối `server` lắng nghe port 80 và có `return 301 https://example.com$request_uri;`.
  3. Khối `server` lắng nghe port 80 và có `return 302 https://$host$request_uri;` (hoặc 308).
  4. Khối `server` lắng nghe port 443 với tham số `ssl` (không cần chuyển hướng, bỏ qua).
  5. Khối `server` lắng nghe cả port 80 và 8080, có `return 301 https://$host$request_uri;`.

- **Không hợp lệ - Thiếu hoàn toàn chuyển hướng (Missing Entirely) - 10 Test Cases:**
  - 6. Khối `server` lắng nghe port 80 không có chỉ thị `return` -> Trả về `add` `return 301 https://$host$request_uri;`.
  - 7. Khối `server` lắng nghe port 80 không có `return` nhưng có khối `location /` phục vụ nội dung -> Trả về `add`.
  - 8. Khối `server` không có tham số port trong chỉ thị `listen` (mặc định Nginx là 80) thiếu `return` -> Trả về `add`.
  - 9. Nhiều khối `server` lắng nghe port 80 đều thiếu `return` -> Trả về `add` cho từng `server`.
  - 10. Khối `server` lắng nghe cả 80 và 443 chung trong một block nhưng thiếu `return` (bad practice) -> Báo lỗi thiếu chuyển hướng (tùy logic xử lý cụ thể, có thể cần tách block).
  - 11. Khối `server` lắng nghe port 80 rỗng (không có directive nào khác ngoài `listen`) -> Trả về `add`.
  - 12. Khối `server` lắng nghe port 80 chỉ chứa `listen` và `server_name`, thiếu `return`.
  - 13. Khối `server` lắng nghe port 80 nằm trong file include thiếu `return`.
  - 14. Chỉ thị chuyển hướng bị comment `# return 301 https://$host$request_uri;` -> Bị coi là thiếu -> `add`.
  - 15. Block `server` lắng nghe port 80 cấu hình làm proxy (`proxy_pass`), quên cấu hình chuyển hướng HTTP sang HTTPS -> Trả về `add`.

- **Không hợp lệ - Chuyển hướng sai hoặc không phải HTTPS (Invalid Redirects) - 7 Test Cases:**
  - 16. Có `return 301 http://$host$request_uri;` (chuyển hướng sang HTTP) -> Trả về `replace` hoặc `add`.
  - 17. Có `return 200 "OK";` trong khối `server` lắng nghe port 80 -> Báo lỗi, trả về `replace`.
  - 18. Có `return 404;` trong khối `server` lắng nghe port 80 -> Báo lỗi, trả về `replace`.
  - 19. Có chuyển hướng tương đối `return 301 /path;` (không ép buộc HTTPS) -> Báo lỗi.
  - 20. Sử dụng `rewrite ^(.*)$ http://$host$1 permanent;` (chuyển hướng sang HTTP) -> Báo lỗi.
  - 21. Chỉ thị `return` thiếu URL (ví dụ: `return 301;`) -> Báo lỗi.
  - 22. Có `return 301 https://$host$request_uri;` nhưng nằm sâu trong khối `location` (không bảo vệ toàn cục khối `server`) -> Trả về `add` ở cấp `server`.

- **Xử lý đa ngữ cảnh (Context Bindings) - 5 Test Cases:**
  - 23. `server` lắng nghe port 80 có `return 301 https...` hợp lệ, nhưng một `location` con bên trong có `return 200` (Nginx ưu tiên return ở server block) -> Hợp lệ.
  - 24. `server` định nghĩa nhiều chỉ thị `listen` (ví dụ: 80, 8080), có duy nhất 1 chỉ thị `return 301 https...` -> Hợp lệ.
  - 25. Chỉ thị `return 301 https...` nằm ở ngoài khối `server` (Global hoặc `http` context) -> Cú pháp lỗi hoặc không đúng chuẩn chuyển hướng HTTP -> Báo lỗi thiếu ở `server`.
  - 26. `return` nằm trong khối `if` (`if ($scheme = http) { return 301 https://$host$request_uri; }`) -> Hợp lệ.
  - 27. Một `server` lắng nghe port 80 có chuyển hướng hợp lệ, một `server` lắng nghe port 80 khác thì không -> Chỉ báo lỗi `add` cho `server` thiếu.

- **Cấu hình đa tệp (Multi-file configurations) - 5 Test Cases:**
  - 28. `nginx.conf` chứa `server` 80 thiếu chuyển hướng, `conf.d/app.conf` chứa `server` 80 có chuyển hướng -> Báo lỗi `add` ở `nginx.conf`.
  - 29. `nginx.conf` không có `server` 80, `conf.d/api.conf` có `server` 80 thiếu chuyển hướng -> Báo lỗi `add` ở `api.conf`.
  - 30. Cả `nginx.conf` và `conf.d/api.conf` đều có `server` 80 thiếu chuyển hướng -> Báo lỗi cho cả 2 file.
  - 31. 3 file cấu hình chứa `server` 80, tất cả đều thiếu chuyển hướng -> Gộp lỗi theo 3 files tương ứng bằng `_group_by_file`.
  - 32. File include nằm sâu trong thư mục con định nghĩa `server` 80 thiếu chuyển hướng -> Trả về `exact_path` và tên file chuẩn xác.

- **Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) - 10 Test Cases:**
  - 33. `exact_path` tính toán chính xác khi thực hiện `add` vào cuối khối `server`.
  - 34. `logical_context` của hành động `add` hoặc `replace` chứa đúng `['http', 'server']`.
  - 35. Xử lý khi giá trị args của `return` chứa dấu ngoặc kép (ví dụ: `return 301 "https://$host$request_uri";`).
  - 36. Xử lý khi chỉ thị `listen` có nhiều tham số đi kèm (ví dụ: `listen 80 default_server reuseport;`).
  - 37. Xác minh thuộc tính `action` là `add` khi thiếu hoàn toàn, và `replace` khi có chuyển hướng nhưng không đúng chuẩn.
  - 38. Xử lý khi khối `server` chỉ chứa cấu hình IPv6 `listen [::]:80;` thiếu `return`.
  - 39. Xử lý khối `server` lắng nghe cả IPv4 và IPv6 (`listen 80;` và `listen [::]:80;`) nhưng thiếu `return`.
  - 40. Hỗ trợ mã chuyển hướng 308 (Permanent Redirect) sang HTTPS `return 308 https://$host$request_uri;` -> Hợp lệ.
  - 41. Xử lý trường hợp sử dụng biến môi trường tùy chỉnh trong URL của `return`.
  - 42. Đảm bảo cấu trúc payload JSON `remediations` khớp hoàn toàn với định dạng chuẩn trong `scan_result.json`, có args `["301", "https://$host$request_uri"]`.
