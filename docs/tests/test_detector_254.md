# Tài liệu Kiểm thử: Detector 254 (CIS Nginx Benchmark - Recommendation 2.5.4)

## Tổng quan về Recommendation 2.5.4 trong CIS Nginx Benchmark:

Đảm bảo NGINX reverse proxy không tiết lộ thông tin backend.
Khi NGINX đóng vai trò reverse proxy, nó có thể chuyển tiếp các header từ ứng dụng backend (VD: `X-Powered-By`, `Server`). Cần loại bỏ các header này trước khi phản hồi cho client để tránh rò rỉ thông tin về công nghệ và phiên bản backend.

## Tổng quan về Detector 254

### Mục tiêu của Detector 254

Kiểm tra tất cả các cấu hình có sử dụng proxy (`proxy_pass` hoặc `fastcgi_pass`) trong toàn bộ cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện chỉ thị `proxy_pass` mà không có `proxy_hide_header X-Powered-By;` và `proxy_hide_header Server;`, hoặc `fastcgi_pass` mà không có `fastcgi_hide_header X-Powered-By;` trong ngữ cảnh có hiệu lực, trả về lỗi kèm hành động `add` để Auto-Remediation khắc phục.

### Cách hoạt động của Detector 254 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` tìm tất cả các chỉ thị `proxy_pass` và `fastcgi_pass`, sau đó kiểm tra xem trong cùng ngữ cảnh (hoặc ngữ cảnh cha như `server`, `http`) có cấu hình ẩn header tương ứng chưa.

1. Xác định vị trí các chỉ thị `proxy_pass` và `fastcgi_pass`.
2. Kiểm tra chuỗi kế thừa (inheritance chain) từ `http` -> `server` -> `location` xem có thiếu `proxy_hide_header` (`X-Powered-By`, `Server`) hoặc `fastcgi_hide_header` (`X-Powered-By`) không. Lưu ý: Nếu một khối con định nghĩa lại mảng chỉ thị `hide_header`, nó sẽ ghi đè khối cha.
3. Nếu thiếu, tạo `action: add` vào khối chứa `proxy_pass` hoặc `fastcgi_pass` tương ứng.
4. Dùng `_group_by_file` gộp các vi phạm theo từng file để Auto-Remediation xử lý.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_254.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                              |
| :------------------------------------------------------------------- | :--------------------- | :---------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc  |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện rò rỉ header    |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector254` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.4"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo NGINX reverse proxy không tiết lộ thông tin backend"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình dựa vào JSON AST từ `crossplane`.

- **Hợp lệ - Ẩn header đầy đủ (Valid Configurations) - 5 Test Cases:**
  1. Có `proxy_pass`, và có đủ `proxy_hide_header X-Powered-By;` cùng `proxy_hide_header Server;` trong cùng khối `location`.
  2. Có `fastcgi_pass`, và có `fastcgi_hide_header X-Powered-By;` trong cùng khối `location`.
  3. Không sử dụng `proxy_pass` hay `fastcgi_pass` -> Bỏ qua, Pass.
  4. Các chỉ thị `hide_header` nằm ở khối `http` (cha), `proxy_pass` nằm ở `location` (con), không bị ghi đè -> Pass.
  5. Cả `proxy_pass` và `fastcgi_pass` cùng tồn tại trong các `location` khác nhau và đều có cấu hình ẩn header đầy đủ -> Pass.

- **Không hợp lệ - Thiếu chỉ thị ẩn header (Missing Directives) - 15 Test Cases:**
  - 6. Có `proxy_pass`, hoàn toàn thiếu `proxy_hide_header X-Powered-By`. -> Trả về `add`.
  - 7. Có `proxy_pass`, hoàn toàn thiếu `proxy_hide_header Server`. -> Trả về `add`.
  - 8. Có `proxy_pass`, thiếu cả 2 header `X-Powered-By` và `Server`. -> Trả về 2 hành động `add`.
  - 9. Có `fastcgi_pass`, thiếu `fastcgi_hide_header X-Powered-By`. -> Trả về `add`.
  - 10. File chứa cả `proxy_pass` và `fastcgi_pass`, thiếu toàn bộ các chỉ thị ẩn header tương ứng. -> Trả về `add` cho tất cả.
  - 11. Có nhiều `location` chứa `proxy_pass`, không nơi nào có `hide_header`.
  - 12. Có nhiều `location` chứa `fastcgi_pass`, không nơi nào có `hide_header`.
  - 13. `proxy_hide_header` có tồn tại, nhưng cấu hình cho header khác (VD: `X-Frame-Options`), vẫn thiếu 2 header bắt buộc.
  - 14. `fastcgi_hide_header` có tồn tại nhưng cấu hình cho header khác.
  - 15. `proxy_pass` nằm trong khối `if` thiếu `hide_header` -> Trả về `add` vào trong `if` hoặc `location` bọc ngoài.
  - 16. `fastcgi_pass` nằm trong khối `if` thiếu `hide_header`.
  - 17. Cấu hình có `proxy_hide_header X-Powered-By` nhưng sai chính tả (VD: `x-power-by` thay vì `X-Powered-By` - Lưu ý case-insensitive theo Nginx). (Test xử lý case).
  - 18. Có `proxy_hide_header` cấu hình qua biến `$header`. (Xử lý fallback an toàn).
  - 19. Chỉ thị `proxy_pass` bị comment (thư viện AST bỏ qua), nhưng có 1 `proxy_pass` khác không bị comment và thiếu header.
  - 20. Có `proxy_pass`, có `proxy_hide_header Server;` nhưng thiếu `X-Powered-By`. -> Báo thiếu 1.

- **Xử lý đa ngữ cảnh và Ghi đè (Context Bindings & Overrides) - 10 Test Cases:**
  - 21. `proxy_hide_header` ở `http`, `proxy_pass` ở `server` -> Pass.
  - 22. `proxy_hide_header` ở `server`, `proxy_pass` ở `location` -> Pass.
  - 23. `proxy_pass` ở `location A`, `proxy_hide_header` ở `location B` -> `location A` thiếu -> Trả về `add` cho A.
  - 24. `fastcgi_hide_header` ở `http`, `fastcgi_pass` ở `location` -> Pass.
  - 25. `fastcgi_pass` ở `location A`, `fastcgi_hide_header` ở `location B` -> Fail cho A -> `add`.
  - 26. Ghi đè cấu hình: `proxy_hide_header` ở `http`, nhưng trong `location` lại có `proxy_hide_header X-Test;` làm mất kế thừa -> `location` thiếu `X-Powered-By` và `Server` -> Trả về `add` ở `location`.
  - 27. Ghi đè cấu hình: `fastcgi_hide_header` ở `server`, nhưng trong `location` khai báo `fastcgi_hide_header X-Other;` -> Trả về `add` ở `location`.
  - 28. Khối `http` có `proxy_hide_header Server`, khối `server` có `proxy_hide_header X-Powered-By`. Do tính chất mảng của Nginx, khối `server` ghi đè khối `http`, làm mất `Server`. -> Báo lỗi thiếu `Server` ở khối `server`.
  - 29. Chỉ thị `proxy_pass` ở global context (lỗi cú pháp Nginx nhưng kiểm tra AST an toàn) -> Báo thiếu.
  - 30. Khối `location` lồng nhau: `location / { proxy_pass ...; location /api { ... } }`. Kiểm tra tính kế thừa lồng sâu.

- **Cấu hình đa tệp (Multi-file configurations) - 7 Test Cases:**
  - 31. `proxy_pass` ở file `conf.d/app.conf`, thiếu `hide_header` -> Báo `add` vào file `app.conf`.
  - 32. `proxy_pass` ở `app.conf`, `proxy_hide_header` ở file gốc `nginx.conf` (`http` block) -> Pass, kế thừa tốt.
  - 33. `fastcgi_pass` ở `app.conf`, thiếu `hide_header` -> Báo `add` vào `app.conf`.
  - 34. `proxy_pass` ở `app.conf`, `proxy_hide_header` ở `nginx.conf` nhưng bị ghi đè bởi `proxy_hide_header` khác ở `app.conf` -> Báo lỗi ở `app.conf`.
  - 35. File 1, 2, 3 đều có `proxy_pass` và cùng thiếu `hide_header`. -> Trả về các hành động `add` cho từng file tương ứng thông qua `_group_by_file`.
  - 36. Lỗi nằm ở file include rất sâu `conf.d/sub/app.conf`. Đảm bảo mapping đường dẫn đúng.
  - 37. `fastcgi_pass` ở nhiều file và thiếu `hide_header`. Dùng `_group_by_file` phân cụm.

- **Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) - 5 Test Cases:**
  - 38. Tính toán đúng `exact_path` khi chèn `proxy_hide_header` vào cuối khối `location` đang có nhiều chỉ thị.
  - 39. Tính toán đúng `exact_path` khi chèn `fastcgi_hide_header` vào `location`.
  - 40. Đảm bảo `logical_context` chứa chính xác ngữ cảnh `['http', 'server', 'location']` cho hành động `add`.
  - 41. Kiểm tra không nhầm lẫn giữa `proxy_hide_header` và `fastcgi_hide_header` (VD: `proxy_pass` nhưng dùng `fastcgi_hide_header` là sai -> Vẫn báo lỗi).
  - 42. Cấu trúc output `remediations` (JSON) khớp hoàn toàn với định dạng chuẩn trong `scan_result.json`.