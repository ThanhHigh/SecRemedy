# Tài liệu Kiểm thử: Detector 531 (CIS Nginx Benchmark - Recommendation 5.3.1)

## Tổng quan về Recommendation 5.3.1 trong CIS Nginx Benchmark:

Đảm bảo header X-Content-Type-Options được cấu hình và kích hoạt.
Header `X-Content-Type-Options` chỉ thị cho trình duyệt không tự đoán (sniff) kiểu MIME của file, giúp ngăn chặn các cuộc tấn công nhầm lẫn kiểu MIME (MIME type confusion). Chỉ thị `nosniff` buộc trình duyệt từ chối file nếu kiểu được khai báo không khớp với ngữ cảnh tải (ví dụ: tải file văn bản như một script).

## Tổng quan về Detector 531

### Mục tiêu của Detector 531

Kiểm tra sự tồn tại và cấu hình đúng đắn của chỉ thị `add_header X-Content-Type-Options "nosniff" always;` trong cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện cấu hình thiếu, sai tham số `nosniff`, hoặc thiếu cờ `always`, detector sẽ trả về lỗi kèm hành động tương ứng (`add`, `replace`) để module Auto-Remediation tự động khắc phục.

### Cách hoạt động của Detector 531 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` để duyệt đệ quy qua các khối `http` và `server`. Tại mỗi khối có khả năng phục vụ request, detector kiểm tra xem có chỉ thị `add_header` nào cấu hình cho `X-Content-Type-Options` không.

- Nếu có, kiểm tra giá trị của nó có đúng là `"nosniff"` (hoặc `nosniff`) và có tham số `always` ở cuối hay không. Nginx cho phép ghi đè các `add_header` ở cấp độ con, nên nếu khối con định nghĩa `add_header` khác (ví dụ `X-Frame-Options`) mà không định nghĩa lại `X-Content-Type-Options`, khối con đó sẽ mất kế thừa.
- Nếu thiếu hoặc sai cấu hình, detector ghi nhận vi phạm bằng `exact_path` và tạo payload hướng dẫn sửa chữa (thêm mới hoặc thay thế chỉ thị hiện tại). Cuối cùng, sử dụng `_group_by_file` để gộp các vi phạm theo từng tệp cấu hình.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_531.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra việc cấu hình X-Content-Type-Options  |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector531` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"5.3.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Đảm bảo header X-Content-Type-Options được cấu hình và kích hoạt"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính như `description`, `audit_procedure`, `impact`, `remediation` để hiển thị Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc phát hiện cấu hình header X-Content-Type-Options trong AST từ `crossplane`.

- **Hợp lệ - Cấu hình chuẩn (Valid Configuration) - 5 Test Cases:**
  - 1. Có `add_header X-Content-Type-Options "nosniff" always;` nằm trong block `server`.
  - 2. Có `add_header X-Content-Type-Options nosniff always;` (không có ngoặc kép) nằm trong block `server`.
  - 3. Cấu hình nằm trong block `http` và áp dụng hợp lệ cho mọi server con.
  - 4. Cấu hình hợp lệ xuất hiện ở cả `http` và `server` (ghi đè hợp lệ).
  - 5. Cấu hình nằm trong block `location` hợp lệ.

- **Không hợp lệ - Thiếu hoặc sai cấu hình (Misconfigured/Missing) - 10 Test Cases:**
  - 6. Hoàn toàn không có chỉ thị `add_header X-Content-Type-Options` trong toàn bộ cấu hình.
  - 7. Có header nhưng thiếu chữ `always` (`add_header X-Content-Type-Options "nosniff";`).
  - 8. Có header với tham số `always` nhưng sai giá trị `nosniff`, ví dụ: `add_header X-Content-Type-Options "sniff" always;`.
  - 9. Sai giá trị: `add_header X-Content-Type-Options "none" always;`.
  - 10. Tên header viết sai chính tả (vd: `X-Content-Type-Option`) dẫn đến thiếu cấu hình hợp lệ.
  - 11. Lệnh `add_header` bị comment đi trong cấu hình.
  - 12. Cấu hình tham số sau cùng sai: `add_header X-Content-Type-Options "nosniff" off;` (không phải always).
  - 13. Có nhiều header `add_header` khác nhau trong cấu hình nhưng không có `X-Content-Type-Options`.
  - 14. Header hợp lệ ở `http` nhưng ở `server` bị ghi đè bằng một `add_header` khác (tạo ra việc mất kế thừa) nên `server` thiếu header này.
  - 15. Thiếu `X-Content-Type-Options` ở cả khối `http` và tất cả các khối `server`.

- **Kiểm tra theo cấp độ và sự kế thừa (Block Levels: http, server, location) - 10 Test Cases:**
  - 16. Thiếu ở `http` và `server` -> Sinh payload `add` vào `http` hoặc `server`.
  - 17. Cấu hình có `X-Content-Type-Options` ở `server` nhưng sai tham số -> Trả về payload sửa (`replace`) tại `server` đó.
  - 18. Cấu hình đúng ở `http`, không có `add_header` nào khác ở `server` -> Hợp lệ do kế thừa.
  - 19. Cấu hình đúng ở `http`, nhưng `server` có `add_header X-Frame-Options ...` -> Mất tính kế thừa, `server` thiếu `X-Content-Type-Options` -> Không hợp lệ.
  - 20. Cấu hình đúng ở `server`, `location` không có `add_header` nào -> Hợp lệ.
  - 21. Cấu hình đúng ở `server`, `location` có `add_header X-XSS-Protection ...` -> Không hợp lệ ở `location` do mất kế thừa.
  - 22. Nested location: `location` cha có `X-Content-Type-Options`, `location` con có `add_header` khác -> Không hợp lệ ở `location` con.
  - 23. Nhiều `server` block: một server có cấu hình chuẩn, một server khác thiếu hoàn toàn -> Vi phạm chỉ tính ở server thiếu.
  - 24. Ghi đè ở `server` với `add_header X-Content-Type-Options "nosniff";` (thiếu always) trong khi `http` đã có đầy đủ -> Không hợp lệ tại `server`.
  - 25. Khối `server` thiếu, khối `location /` có cấu hình chuẩn, nhưng khối `location /api` không có gì -> Vi phạm hiển thị ở `server` / `location /api`.

- **Cấu hình đa tệp (Multi-file configurations) - 10 Test Cases:**
  - 26. `nginx.conf` cấu hình chuẩn ở `http`, các file `conf.d/*.conf` kế thừa bình thường (không có `add_header` nào) -> Hợp lệ.
  - 27. `nginx.conf` cấu hình chuẩn ở `http`, nhưng `conf.d/admin.conf` dùng một `add_header` khác gây mất kế thừa -> Vi phạm ở `admin.conf`.
  - 28. `nginx.conf` rỗng phần bảo mật, nhưng tất cả `conf.d/*.conf` đều định nghĩa chuẩn ở cấp `server` -> Hợp lệ.
  - 29. `nginx.conf` rỗng, `admin.conf` có, `web.conf` thiếu hoàn toàn -> Vi phạm hiển thị ở `web.conf`.
  - 30. Cấu hình header được định nghĩa trong `security_headers.conf` và được `include` hợp lệ ở `server` -> Hợp lệ.
  - 31. Lệnh `include security_headers.conf` ở trong `location` -> Hợp lệ cho riêng `location` đó.
  - 32. File `security_headers.conf` được include nhưng thiếu tham số `always` cho `X-Content-Type-Options` -> Vi phạm trỏ vào file `security_headers.conf`.
  - 33. Một block `server` bị tách ra qua nhiều file `include`, cuối cùng cấu hình vẫn không chứa header `X-Content-Type-Options` -> Không hợp lệ.
  - 34. Dùng `include` để nạp tệp cấu hình nhưng tệp đó không tồn tại (AST rỗng phần includes) -> Coi như thiếu.
  - 35. Cấu hình `http` ở file chính đủ chuẩn, nhưng file phụ chứa khối `server` khai báo `add_header` khác làm mất kế thừa -> Vi phạm tại file phụ.

- **Cấu trúc AST, Remediation Payload & Edge Cases - 7 Test Cases:**
  - 36. Lệnh `add_header` có cấu trúc AST sai hoặc chứa quá nhiều tham số -> Xử lý báo lỗi/tính là thiếu.
  - 37. Payload `add` chèn chỉ thị `add_header X-Content-Type-Options "nosniff" always;` vào khối `server` (hoặc `http`) khi phát hiện vi phạm do thiếu hoàn toàn.
  - 38. Payload `replace` thay thế chính xác chỉ thị hiện có nếu nó đang bị thiếu từ khóa `always`.
  - 39. Payload `replace` sửa tham số bị sai (như `sniff` thành `"nosniff" always`).
  - 40. Payload đảm bảo `exact_path` mang giá trị array index chính xác để Auto-Remediation áp dụng đúng dòng cấu hình.
  - 41. Nếu xuất hiện nhiều chỉ thị `add_header X-Content-Type-Options` trong cùng một block, kiểm tra khả năng xử lý trùng lặp và xác thực đúng giá trị cuối cùng.
  - 42. Xử lý không phân biệt hoa thường tên header: `X-CONTENT-TYPE-OPTIONS`.
