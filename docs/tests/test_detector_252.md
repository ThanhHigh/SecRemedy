# Tài liệu Kiểm thử: Detector 252 (CIS Nginx Benchmark - Recommendation 2.5.2)

## Tổng quan về Recommendation 2.5.2 trong CIS Nginx Benchmark:

Đảm bảo các trang lỗi mặc định và trang index.html không tham chiếu đến NGINX. Các trang lỗi mặc định (ví dụ: 404, 500) thường chứa dấu hiệu nhận dạng NGINX. Cần thay thế bằng các trang tùy chỉnh không chứa thông tin phần mềm máy chủ, giúp ngăn kẻ tấn công nhận dạng công nghệ và thu thập thông tin tình báo.

## Tổng quan về Detector 252

### Mục tiêu của Detector 252

Kiểm tra sự hiện diện của chỉ thị `error_page` (đặc biệt cho các mã lỗi phổ biến như 404 và 50x) trong toàn bộ cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện cấu hình không định nghĩa `error_page` tùy chỉnh để che giấu trang lỗi mặc định của NGINX, trả về lỗi kèm hành động `add` để Auto-Remediation tự động bổ sung cấu hình trang lỗi an toàn.

### Cách hoạt động của Detector 252 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` tìm tất cả chỉ thị `error_page` và các khối `http`, `server`.

1. Kiểm tra khối `http` hoặc các khối `server` có chứa `error_page` xử lý các lỗi 404 và 500 502 503 504 hay không.
2. Nếu khối `server` (hoặc `http` bao ngoài nó) không định nghĩa `error_page` tùy chỉnh, ghi nhận vi phạm với `action: add` để thêm `error_page` vào khối `server`.
3. Dùng `_group_by_file` gộp các vi phạm theo từng file để Auto-Remediation xử lý hiệu quả.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_252.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện `error_page`   |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector252` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo các trang lỗi mặc định và trang index.html không tham chiếu đến NGINX"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Hợp lệ - Đã định nghĩa error_page (Valid Configurations) - 5 Test Cases:**
  1. Khối `http` chứa `error_page 404` và `error_page 500 502 503 504`.
  2. Khối `server` chứa `error_page 404` và `error_page 500 502 503 504` (không có ở `http`).
  3. Khối `http` định nghĩa `error_page 404`, khối `server` định nghĩa `error_page 50x`.
  4. Nhiều khối `server` đều tự định nghĩa `error_page` đầy đủ.
  5. Cấu hình `error_page` có đổi mã HTTP response (`error_page 404 =200 /empty.html;`).

- **Không hợp lệ - Thiếu hoàn toàn error_page (Missing Entirely) - 10 Test Cases:**
  - 6. Khối `http` trống, không có `error_page` -> Trả về `add` `error_page` vào `http` hoặc `server`.
  - 7. Khối `server` trống, không có `error_page` (và `http` cũng không) -> Trả về `add`.
  - 8. Cấu hình chỉ có `http` với các directive khác, thiếu `error_page` -> Trả về `add`.
  - 9. Cấu hình có nhiều `server`, không `server` nào có `error_page` -> Trả về `add` cho từng `server`.
  - 10. `location` có `error_page` nhưng `server` tổng thể không có (không bảo vệ toàn cục) -> Trả về `add` ở `server`.
  - 11. File cấu hình rỗng.
  - 12. Khối `server` chỉ có `listen` và `server_name`, thiếu `error_page`.
  - 13. Khối `server` nằm trong file include thiếu `error_page`.
  - 14. Chỉ thị bị comment `# error_page 404 /404.html;` -> Bị coi là thiếu -> `add`.
  - 15. Block `server` cấu hình làm proxy, nhưng quên cấu hình `error_page` chặn lỗi proxy.

- **Không hợp lệ - Thiếu một số mã lỗi quan trọng (Partial Missing) - 7 Test Cases:**
  - 16. Có `error_page 404` nhưng thiếu nhóm `500 502 503 504` -> Trả về `add` nhóm 50x.
  - 17. Có `error_page 50x` nhưng thiếu `404` -> Trả về `add` mã 404.
  - 18. Có `error_page` cho lỗi 403, nhưng thiếu 404 và 50x -> Trả về `add` mã 404, 50x.
  - 19. Khối `http` có `404`, `server` ghi đè bằng `error_page 403` (làm mất `50x` và `404` do override) -> Báo lỗi ở `server`.
  - 20. Cấu hình `error_page` gộp `404 500 502`, thiếu `503 504`.
  - 21. `error_page` được khai báo nhưng không trỏ tới file cụ thể (cú pháp sai).
  - 22. Có `error_page 500 502 503 504` nhưng args bị tách làm nhiều directive nhỏ lẻ, vẫn hợp lệ -> (Test case đặc biệt kiểm tra khả năng parse).

- **Xử lý đa ngữ cảnh (Context Bindings) - 5 Test Cases:**
  - 23. `error_page` nằm trong `http` -> Tất cả `server` bên trong được thừa kế (Hợp lệ, không báo lỗi).
  - 24. `error_page` nằm trong `http`, nhưng một `server` con khai báo `error_page 403` (sẽ xoá tính thừa kế) -> Báo lỗi `add` 404 và 50x cho `server` đó.
  - 25. `error_page` nằm ngoài khối `http` (Global context) -> Cú pháp không hợp lệ theo Nginx, báo thiếu.
  - 26. `error_page` nằm trong `if` block -> Không khuyến khích, báo lỗi để add vào `server`.
  - 27. Một `server` có `error_page` đầy đủ, một `server` khác thì không -> Chỉ báo lỗi `add` cho `server` thiếu.

- **Cấu hình đa tệp (Multi-file configurations) - 5 Test Cases:**
  - 28. `nginx.conf` thiếu `error_page`, file include `conf.d/app.conf` định nghĩa khối `server` thiếu `error_page` -> Báo lỗi `add` ở `app.conf`.
  - 29. `nginx.conf` định nghĩa `error_page` trong `http`, `conf.d/api.conf` không định nghĩa lại -> Hợp lệ (thừa kế tốt).
  - 30. `nginx.conf` có `error_page`, `conf.d/api.conf` ghi đè `error_page 401` -> Báo lỗi `add` 404/50x ở `api.conf`.
  - 31. 3 files cấu hình `server`, tất cả đều thiếu `error_page` -> Gộp lỗi theo 3 files tương ứng bằng `_group_by_file`.
  - 32. File include nằm sâu trong nhiều cấp thư mục thiếu `error_page` -> `exact_path` và tên file chuẩn xác.

- **Cấu trúc lồng nhau và ngoại lệ (Nested structures & edge cases) - 10 Test Cases:**
  - 33. `exact_path` tính toán chính xác khi `add` vào cuối khối `server`.
  - 34. `logical_context` của `add` chứa đúng `['http', 'server']`.
  - 35. Xử lý khi giá trị args của `error_page` được viết bằng chuỗi có dấu ngoặc kép.
  - 36. Xử lý nhiều chỉ thị `error_page` định nghĩa trùng lặp.
  - 37. Xác minh thuộc tính `action` luôn là `add` khi phát hiện thiếu trang lỗi mặc định.
  - 38. Xác minh không có hành động `delete` hay `replace` bị tạo nhầm.
  - 39. Xử lý khi `server` block rỗng (không có directives bên trong).
  - 40. Xử lý khối `http` rỗng (thêm `error_page` vào `http` hoặc `server`).
  - 41. Xử lý khi biến môi trường được dùng trong tham số của `error_page`.
  - 42. Đảm bảo cấu trúc payload JSON `remediations` khớp hoàn toàn với `scan_result.json`, có args `["404", "/custom_404.html"]` và nhóm 50x tương ứng.
