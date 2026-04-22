# Tài liệu Kiểm thử: Detector 532 (CIS Nginx Benchmark - Recommendation 5.3.2)

## Tổng quan về Recommendation 5.3.2 trong CIS Nginx Benchmark:

Đảm bảo Content Security Policy (CSP) được bật và cấu hình hợp lý (Thủ công).
Content Security Policy (CSP) là một HTTP response header cho phép quản trị viên khai báo các nguồn nội dung được phép tải trên trang. Đây là cơ chế phát hiện và giảm thiểu các cuộc tấn công như Cross-Site Scripting (XSS) và tiêm dữ liệu. Ngoài ra, chỉ thị `frame-ancestors` của CSP thay thế header `X-Frame-Options` để chống Clickjacking.

## Tổng quan về Detector 532

### Mục tiêu của Detector 532

Kiểm tra sự tồn tại và cấu hình đúng đắn của header `Content-Security-Policy` trong cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện cấu hình thiếu `Content-Security-Policy` hoặc thiếu các chỉ thị quan trọng (như `default-src`, hoặc `frame-ancestors`), hoặc sử dụng chỉ thị không an toàn (`unsafe-inline`, `unsafe-eval`), detector sẽ trả về lỗi kèm hành động tương ứng (`add`, `replace`) để module Auto-Remediation tự động khắc phục.

### Cách hoạt động của Detector 532 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` để duyệt đệ quy qua các khối `http` và `server`. Tại mỗi khối có khả năng phục vụ request, detector kiểm tra xem có chỉ thị `add_header` nào cấu hình cho `Content-Security-Policy` không.

- Nếu có, kiểm tra xem nội dung của header có chứa ít nhất một chỉ thị `default-src` (ví dụ: `'self'` hoặc `'none'`) và `frame-ancestors` hay không. Ngoài ra cần có tham số `always`. Nginx cho phép ghi đè các `add_header` ở cấp độ con, nên nếu khối con định nghĩa `add_header` khác mà không định nghĩa lại `Content-Security-Policy`, khối con đó sẽ mất kế thừa.
- Nếu thiếu hoặc cấu hình không an toàn (ví dụ: chứa `unsafe-inline` hoặc `unsafe-eval`), detector ghi nhận vi phạm bằng `exact_path` và tạo payload hướng dẫn sửa chữa (thêm mới hoặc thay thế chỉ thị hiện tại). Cuối cùng, sử dụng `_group_by_file` để gộp các vi phạm theo từng tệp cấu hình.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_532.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra việc cấu hình Content-Security-Policy |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector532` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"5.3.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Đảm bảo Content Security Policy (CSP) được bật và cấu hình hợp lý (Thủ công)"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính như `description`, `audit_procedure`, `impact`, `remediation` để hiển thị Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc phát hiện cấu hình header Content-Security-Policy trong AST từ `crossplane`.

- **Hợp lệ - Cấu hình chuẩn (Valid Configuration) - 5 Test Cases:**
  - 1. Có `add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; form-action 'self';" always;` nằm trong block `server`.
  - 2. Cấu hình nằm trong block `http` và áp dụng hợp lệ cho mọi server con.
  - 3. Cấu hình hợp lệ xuất hiện ở cả `http` và `server` (ghi đè hợp lệ).
  - 4. Cấu hình nằm trong block `location` hợp lệ.
  - 5. Cấu hình có `Content-Security-Policy-Report-Only` hợp lệ (được chấp nhận thay thế hoặc dùng trong giai đoạn test).

- **Không hợp lệ - Thiếu hoặc sai cấu hình cơ bản (Misconfigured/Missing) - 10 Test Cases:**
  - 6. Hoàn toàn không có chỉ thị `add_header Content-Security-Policy` trong toàn bộ cấu hình.
  - 7. Có header nhưng thiếu chữ `always`.
  - 8. Có header nhưng thiếu chỉ thị `default-src`.
  - 9. Có header nhưng thiếu chỉ thị `frame-ancestors`.
  - 10. Tên header viết sai chính tả (vd: `Content-Security-Polic`) dẫn đến thiếu cấu hình hợp lệ.
  - 11. Lệnh `add_header` bị comment đi trong cấu hình.
  - 12. Cấu hình tham số sau cùng sai: `add_header Content-Security-Policy "..." off;` (không phải always).
  - 13. Có nhiều header `add_header` khác nhau trong cấu hình nhưng không có `Content-Security-Policy`.
  - 14. Policy chứa tham số rủi ro: `unsafe-inline`.
  - 15. Policy chứa tham số rủi ro: `unsafe-eval`.

- **Kiểm tra theo cấp độ và sự kế thừa (Block Levels: http, server, location) - 10 Test Cases:**
  - 16. Thiếu ở `http` và `server` -> Sinh payload `add` vào `http` hoặc `server`.
  - 17. Cấu hình có `Content-Security-Policy` ở `server` nhưng sai tham số -> Trả về payload sửa (`replace`) tại `server` đó.
  - 18. Cấu hình đúng ở `http`, không có `add_header` nào khác ở `server` -> Hợp lệ do kế thừa.
  - 19. Cấu hình đúng ở `http`, nhưng `server` có `add_header X-Frame-Options ...` -> Mất tính kế thừa, `server` thiếu `Content-Security-Policy` -> Không hợp lệ.
  - 20. Cấu hình đúng ở `server`, `location` không có `add_header` nào -> Hợp lệ.
  - 21. Cấu hình đúng ở `server`, `location` có `add_header X-XSS-Protection ...` -> Không hợp lệ ở `location` do mất kế thừa.
  - 22. Nested location: `location` cha có CSP, `location` con có `add_header` khác -> Không hợp lệ ở `location` con.
  - 23. Nhiều `server` block: một server có cấu hình chuẩn, một server khác thiếu hoàn toàn -> Vi phạm chỉ tính ở server thiếu.
  - 24. Ghi đè ở `server` với CSP thiếu `always` trong khi `http` đã có đầy đủ -> Không hợp lệ tại `server`.
  - 25. Khối `server` thiếu, khối `location /` có cấu hình chuẩn, nhưng khối `location /api` không có gì -> Vi phạm hiển thị ở `server` / `location /api`.

- **Cấu hình đa tệp (Multi-file configurations) - 10 Test Cases:**
  - 26. `nginx.conf` cấu hình chuẩn ở `http`, các file `conf.d/*.conf` kế thừa bình thường (không có `add_header` nào) -> Hợp lệ.
  - 27. `nginx.conf` cấu hình chuẩn ở `http`, nhưng `conf.d/admin.conf` dùng một `add_header` khác gây mất kế thừa -> Vi phạm ở `admin.conf`.
  - 28. `nginx.conf` rỗng phần bảo mật, nhưng tất cả `conf.d/*.conf` đều định nghĩa CSP chuẩn ở cấp `server` -> Hợp lệ.
  - 29. `nginx.conf` rỗng, `admin.conf` có, `web.conf` thiếu hoàn toàn -> Vi phạm hiển thị ở `web.conf`.
  - 30. Cấu hình header được định nghĩa trong `security_headers.conf` và được `include` hợp lệ ở `server` -> Hợp lệ.
  - 31. Lệnh `include security_headers.conf` ở trong `location` -> Hợp lệ cho riêng `location` đó.
  - 32. File `security_headers.conf` được include nhưng thiếu tham số `always` -> Vi phạm trỏ vào file `security_headers.conf`.
  - 33. Một block `server` bị tách ra qua nhiều file `include`, cuối cùng cấu hình vẫn không chứa CSP -> Không hợp lệ.
  - 34. Dùng `include` để nạp tệp cấu hình nhưng tệp đó không tồn tại (AST rỗng phần includes) -> Coi như thiếu.
  - 35. Cấu hình `http` ở file chính đủ chuẩn, nhưng file phụ chứa khối `server` khai báo `add_header` khác làm mất kế thừa -> Vi phạm tại file phụ.

- **Cấu trúc AST, Remediation Payload & Edge Cases - 7 Test Cases:**
  - 36. Lệnh `add_header` có cấu trúc AST sai hoặc chứa quá nhiều tham số -> Xử lý báo lỗi/tính là thiếu.
  - 37. Payload `add` chèn chỉ thị `add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self'; form-action 'self';" always;` vào khối `server` (hoặc `http`) khi phát hiện vi phạm do thiếu hoàn toàn.
  - 38. Payload `replace` thay thế chính xác chỉ thị hiện có nếu nó đang bị thiếu từ khóa `always` hoặc thiếu `frame-ancestors`.
  - 39. Payload `replace` loại bỏ các tham số rủi ro như `unsafe-inline` khỏi CSP hiện tại.
  - 40. Payload đảm bảo `exact_path` mang giá trị array index chính xác để Auto-Remediation áp dụng đúng dòng cấu hình.
  - 41. Nếu xuất hiện nhiều chỉ thị `Content-Security-Policy` trong cùng một block, kiểm tra khả năng xử lý trùng lặp và xác thực đúng giá trị hợp lệ cuối cùng.
  - 42. Xử lý không phân biệt hoa thường tên header: `CONTENT-SECURITY-POLICY`.
