# Tài liệu Kiểm thử: Detector 251 (CIS Nginx Benchmark - Recommendation 2.5.1)

## Tổng quan về Recommendation 2.5.1 trong CIS Nginx Benchmark:

Đảm bảo chỉ thị `server_tokens` được đặt thành `off`.
Chỉ thị `server_tokens` chịu trách nhiệm hiển thị số phiên bản NGINX và hệ điều hành trên các trang lỗi và trong trường header HTTP `Server`. Thông tin này không nên được hiển thị để tránh kẻ tấn công dò quét và nhắm mục tiêu vào các lỗ hổng đã biết.

## Tổng quan về Detector 251

### Mục tiêu của Detector 251

Kiểm tra tất cả các chỉ thị `server_tokens` trong toàn bộ cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện chỉ thị `server_tokens` không được đặt thành `off` (ví dụ: `on`, `build`) hoặc bị thiếu trong khối `http`, trả về lỗi kèm hành động `replace` hoặc `add` để Auto-Remediation khắc phục.

### Cách hoạt động của Detector 251 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` tìm tất cả chỉ thị `server_tokens`.

1. Kiểm tra khối `http` có chứa `server_tokens off;` hay không. Nếu không có, tạo `action: add` cho khối `http`.
2. Quét các chỉ thị `server_tokens` đang tồn tại trong `http`, `server`, `location`. Nếu giá trị khác `off` (vd: `on`), ghi nhận vi phạm với `action: replace` thành `off`.
3. Dùng `_group_by_file` gộp các vi phạm theo từng file để Auto-Remediation xử lý.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_251.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                              |
| :------------------------------------------------------------------- | :--------------------- | :---------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc  |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện `server_tokens` |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector251` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo chỉ thị server_tokens được đặt thành 'off'"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Hợp lệ - `server_tokens off` (Valid Configurations) - 5 Test Cases:**
  1. Chỉ chứa `server_tokens off;` trong khối `http`.
  2. Khối `http` có `server_tokens off;` và khối `server` cũng có `server_tokens off;`.
  3. Khối `http` có `server_tokens off;` và nhiều khối `server` không định nghĩa lại.
  4. Khối `http` có `server_tokens off;` và khối `location` cũng có `server_tokens off;`.
  5. Cấu trúc lồng sâu `http` -> `server` -> `location` đều có `server_tokens off;`.

- **Không hợp lệ - Giá trị sai (Invalid Values) - 10 Test Cases:**
  - 6. Khối `http` chứa `server_tokens on;` -> Trả về `replace` thành `off`.
  - 7. Khối `http` chứa `server_tokens build;` -> Trả về `replace` thành `off`.
  - 8. Khối `server` chứa `server_tokens on;` -> Trả về `replace`.
  - 9. Khối `location` chứa `server_tokens on;` -> Trả về `replace`.
  - 10. `http` có `off`, nhưng `server` có `on` -> Chỉ `replace` ở `server`.
  - 11. `http` có `on`, `server` có `off` -> `replace` ở `http`.
  - 12. Nhiều khối `server` đều chứa `server_tokens on;`.
  - 13. Khối `http` chứa `server_tokens ON;` (In hoa) -> Trả về `replace`.
  - 14. Khối `http` có khoảng trắng dư thừa `server_tokens  on ;`.
  - 15. Có 2 chỉ thị `server_tokens` trong cùng 1 khối (1 `on`, 1 `off`).

- **Không hợp lệ - Bị thiếu (Missing Directive) - 7 Test Cases:**
  - 16. Khối `http` trống, không có `server_tokens` -> Trả về `add` vào `http`.
  - 17. Khối `http` có các chỉ thị khác nhưng thiếu `server_tokens` -> Trả về `add`.
  - 18. Không có khối `http` nào trong cấu hình (cấu hình rỗng).
  - 19. Khối `server` không có `server_tokens`, và `http` cũng thiếu -> Báo thiếu `add` ở `http`.
  - 20. File cấu hình chỉ có khối `server` (không thấy `http`) và thiếu `server_tokens` -> Trả về `add`.
  - 21. Thiếu `server_tokens` trong nhiều file khác nhau nhưng file gốc có khối `http`.
  - 22. Chỉ thị bị comment `# server_tokens off;` (thư viện AST bỏ qua) -> Bị coi là thiếu -> `add`.

- **Xử lý đa ngữ cảnh (Context Bindings) - 5 Test Cases:**
  - 23. `server_tokens off` nằm trong `server` nhưng thiếu ở `http` -> Vẫn yêu cầu `add` ở `http` (theo CIS phải disable globally).
  - 24. `server_tokens on` nằm ở cả `http` và `server` -> `replace` cả hai.
  - 25. `server_tokens` nằm ngoài khối `http` (Global context) với giá trị `on` -> Bắt lỗi `replace`.
  - 26. `server_tokens` nằm trong `if` block với giá trị `on`.
  - 27. `server_tokens` được cấu hình qua biến `$val`.

- **Cấu hình đa tệp (Multi-file configurations) - 5 Test Cases:**
  - 28. `nginx.conf` thiếu `server_tokens`, `conf.d/default.conf` có `server_tokens on;` -> Lỗi ở cả 2 file (`add` ở nginx.conf, `replace` ở default.conf).
  - 29. `nginx.conf` có `server_tokens off;`, `conf.d/api.conf` có `server_tokens on;` -> Chỉ báo lỗi `replace` ở file `api.conf`.
  - 30. 3 files, mỗi file đều có `server_tokens on;` trong `server` block -> Gom lỗi theo 3 files bằng `_group_by_file`.
  - 31. File include nằm sâu `conf.d/sub/app.conf` chứa vi phạm -> `exact_path` và file mapping chuẩn xác.
  - 32. Nhiều file include, không file nào có `server_tokens` -> Báo lỗi `add` vào file chứa khối `http` (thường là `nginx.conf`).

- **Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) - 10 Test Cases:**
  - 33. `exact_path` tính toán đúng khi `server_tokens` là phần tử cuối cùng trong `http`.
  - 34. `exact_path` tính toán đúng khi phải `add` vào `block` rỗng.
  - 35. `logical_context` của `add` chứa đúng `['http']`.
  - 36. `logical_context` của `replace` chứa đúng `['http', 'server', 'location']`.
  - 37. Xử lý khi giá trị là chuỗi có ngoặc kép `"on"` hoặc `'on'`.
  - 38. Xử lý khi giá trị là chuỗi có ngoặc kép `"off"` hoặc `'off'`.
  - 39. Bỏ qua cấu hình của module bên thứ ba có tên tương tự (nếu có).
  - 40. Xác minh thuộc tính `action` là `replace` khi directive đã tồn tại.
  - 41. Xác minh thuộc tính `action` là `add` khi directive chưa tồn tại.
  - 42. Đảm bảo cấu trúc payload JSON `remediations` khớp hoàn toàn với `scan_result.json`.
