# Tài liệu Kiểm thử: Detector 251 (CIS Nginx Benchmark - Recommendation 2.5.1)

## Tổng quan về Recommendation 2.5.1 trong CIS Nginx Benchmark:

Chỉ thị `server_tokens` chịu trách nhiệm hiển thị phiên bản NGINX và hệ điều hành trên các trang lỗi và trong trường header HTTP `Server`. Thông tin này không nên được hiển thị để tránh kẻ tấn công thu thập thông tin và khai thác các lỗ hổng đã biết. Giá trị mặc định là `on`. CIS yêu cầu cấu hình `server_tokens off;` trong block `http` để vô hiệu hóa hiển thị phiên bản trên toàn hệ thống.

## Tổng quan về Detector 251

### Mục tiêu của Detector 251

Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Detector phân tích cấu trúc cây để tìm chỉ thị `server_tokens`. Đầu ra là danh sách các uncompliances (JSON) chứa thông tin các block hoặc file thiếu cấu hình an toàn hoặc cấu hình sai (đặt là `on` hoặc giá trị khác `off`) để chuyển cho module Auto-Remediation khắc phục.

### Cách hoạt động của Detector 251 dựa trên BaseRecom

Kế thừa `BaseRecom`. Quét toàn bộ AST để tìm các block `http`, `server`, và `location`. Detector đánh giá giá trị của `server_tokens`. Nếu `server_tokens` không được đặt thành `off` tại block `http` (và không bị ghi đè thành `on` ở các block con), hoặc bị ghi đè thành `on` ở block `server`/`location`, detector sẽ đánh dấu là uncompliance.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_251.py):

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

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector251` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Ensure server_tokens directive is set to off"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description`, `audit_procedure`, `impact`, và `remediation` để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Trường hợp cấu hình tuân thủ (Compliant) (10 test cases):**
  1. `server_tokens off;` ở block `http`.
  2. `server_tokens off;` ở block `http`, không có khai báo lại ở `server`.
  3. `server_tokens off;` ở block `http`, `server_tokens off;` ở block `server`.
  4. `server_tokens off;` ở block `http`, `server_tokens off;` ở block `location`.
  5. Không có `http` block (file trống, tuân thủ mặc định).
  6. File chỉ chứa các block/chỉ thị không liên quan, cấu hình an toàn được kế thừa.
  7. Nhiều block `http` đều có `server_tokens off;`.
  8. `server_tokens off;` khai báo cùng nhiều chỉ thị khác trong `http`.
  9. `server_tokens` được set `off` với cú pháp viết hoa/thường: `OFF`.
  10. Cấu hình an toàn với cấu trúc lồng nhau phức tạp (`http` -> nhiều `server` -> nhiều `location`).

- **Trường hợp vi phạm thiếu chỉ thị (Missing Directive Uncompliances) (10 test cases):**
  11. Hoàn toàn không khai báo `server_tokens` trong toàn bộ file.
  12. Block `http` tồn tại nhưng không chứa `server_tokens`.
  13. Có block `server` nhưng `http` không khai báo `server_tokens`.
  14. Nhiều block `http` nhưng thiếu `server_tokens` ở 1 block.
  15. Thiếu `server_tokens` trong block `http` nhưng có khai báo ở các cấp khác không đầy đủ.
  16. Block `http` rỗng `http {}`.
  17. Thiếu ở `http`, có `server_tokens off;` ở một số `server` nhưng sót ở `server` khác.
  18. Cấu hình có `location` không thừa kế cấu hình an toàn từ cha.
  19. File cấu hình thiếu ngữ cảnh `http` hoàn toàn khi phân tích độc lập.
  20. Chỉ thị `server_tokens` bị comment-out (crossplane bỏ qua, tính là thiếu).

- **Trường hợp vi phạm cấu hình sai (Misconfigured Uncompliances) (12 test cases):**
  21. `server_tokens on;` ở block `http`.
  22. `server_tokens on;` ở block `server`.
  23. `server_tokens on;` ở block `location`.
  24. `server_tokens off;` ở `http`, nhưng bị ghi đè `server_tokens on;` ở `server`.
  25. `server_tokens off;` ở `http`, nhưng bị ghi đè `server_tokens on;` ở `location`.
  26. `server_tokens` có giá trị không hợp lệ (ví dụ: `build`, chuỗi phiên bản).
  27. Nhiều block `http`, một block chứa `server_tokens on;`.
  28. Lồng nhau: `http` (off) -> `server` (off) -> `location` (on).
  29. Lồng nhau: `http` (off) -> `server` (on) -> `location` (off). Vẫn vi phạm ở cấp `server`.
  30. Khai báo `server_tokens on;` lặp lại nhiều lần.
  31. Khai báo `server_tokens` thiếu tham số `server_tokens ;`.
  32. `server_tokens on;` nằm trong `if` block bên trong `server` hoặc `location`.

- **Trường hợp quét đa tệp tin (Multi-file & Includes Integration) (10 test cases):**
  33. `nginx.conf` (`server_tokens off;`) include `conf.d/web.conf` (`server_tokens on;`). Lỗi ở `web.conf`.
  34. `nginx.conf` (thiếu) include `conf.d/web.conf` (thiếu).
  35. `nginx.conf` (`server_tokens on;`) include `conf.d/web.conf` (`server_tokens off;`). Lỗi ở `nginx.conf`.
  36. Include file rỗng, `nginx.conf` thiếu `server_tokens`.
  37. `server_tokens off;` ở file include đầu, nhưng file include thứ hai ghi đè `on`.
  38. Cấu trúc `http` trải dài trên nhiều file include lồng nhau.
  39. Ghi đè `server_tokens on;` trong `location` ở file được include sâu 3 cấp.
  40. Bỏ qua file include không tồn tại, kiểm tra `server_tokens` trên file hợp lệ.
  41. `nginx.conf` chuẩn, `vhost.conf` thiếu khai báo đè an toàn khi cấu hình riêng.
  42. `server_tokens on;` ở `proxy.conf` được include vào nhiều block `server` khác nhau.