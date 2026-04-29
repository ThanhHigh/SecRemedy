# Tài liệu Kiểm thử: Detector 253 (CIS Nginx Benchmark - Recommendation 2.5.3)

## Tổng quan về Recommendation 2.5.3 trong CIS Nginx Benchmark:

Đảm bảo vô hiệu hóa việc phục vụ các file ẩn.
Các file và thư mục ẩn (bắt đầu bằng dấu chấm, ví dụ: `.git`, `.env`) thường chứa siêu dữ liệu nhạy cảm, lịch sử quản lý phiên bản hoặc cấu hình môi trường. Việc phục vụ các file này cần được vô hiệu hóa trên toàn cục để tránh rò rỉ thông tin dẫn đến nguy cơ bị xâm nhập hệ thống. Cần lưu ý cấu hình ngoại lệ cho `.well-known/acme-challenge/` nếu sử dụng Let's Encrypt, và quy tắc này phải đặt trước quy tắc chặn file ẩn.

## Tổng quan về Detector 253

### Mục tiêu của Detector 253

Kiểm tra tất cả các khối `server` trong toàn bộ cấu hình NGINX để đảm bảo có cấu hình chặn truy cập file ẩn (`location ~ /\.`). Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON) để chuyển cho module Auto-Remediation. Nếu một khối `server` không có khối `location` chặn file ẩn hợp lệ, Detector sẽ sinh ra hành động `add` để chèn thêm quy tắc chặn (bao gồm cả ngoại lệ cho Let's Encrypt).

### Cách hoạt động của Detector 253 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` tìm tất cả chỉ thị `server`.

1. Quét từng khối `server` để tìm khối `location` có đối số khớp với regex `~` và `/\.`.
2. Nếu khối `location` này tồn tại, kiểm tra xem bên trong có chứa chỉ thị `deny` với đối số `all` hay không.
3. Nếu không tìm thấy khối `location` chặn file ẩn, hoặc khối đó không có `deny all`, tạo một vi phạm với `action: add` vào khối `server` đó. Payload thêm mới sẽ bao gồm cả khối ngoại lệ `location ^~ /.well-known/acme-challenge/` (allow all) và khối chặn `location ~ /\. ` (deny all, return 404).
4. Dùng `_group_by_file` gộp các vi phạm theo từng file để Auto-Remediation xử lý.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_253.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện block location |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector253` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.3"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề là `"Đảm bảo vô hiệu hóa việc phục vụ các file ẩn"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ thuộc tính `description`, `audit_procedure`, `impact`, `remediation`.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Hợp lệ - Cấu hình an toàn (Valid Configurations) - 5 Test Cases:**
  1. Khối `server` chứa cả ngoại lệ `location ^~ /.well-known/acme-challenge/` và quy tắc chặn `location ~ /\. ` với `deny all;`.
  2. Khối `server` chỉ chứa quy tắc chặn `location ~ /\. ` với `deny all;` (không có Let's Encrypt exception).
  3. Nhiều khối `server` trong cấu hình, tất cả đều có cấu hình chặn file ẩn.
  4. Chỉ thị `deny all;` và `return 404;` cùng tồn tại hợp lệ trong khối `location ~ /\. `.
  5. Quy tắc ngoại lệ `acme-challenge` được đặt _trước_ quy tắc chặn file ẩn `~ /\. `.

- **Không hợp lệ - Thiếu cấu hình (Missing Configuration) - 10 Test Cases:**
  - 6. Khối `server` hoàn toàn không có khối `location` nào -> Trả về `add` khối chặn file ẩn.
  - 7. Khối `server` có các `location` khác (vd: `/`) nhưng thiếu `location ~ /\. ` -> Trả về `add`.
  - 8. Nhiều khối `server`, một số có quy tắc chặn, một số không -> Trả về `add` cho các khối bị thiếu.
  - 9. Khối `server` trống rỗng -> Trả về `add`.
  - 10. File cấu hình không có khối `server` nào (chỉ có `http`) -> Bỏ qua (không báo lỗi vì không có server để truy cập).
  - 11. Thiếu quy tắc chặn trong `nginx.conf` tại khối `server` mặc định.
  - 12. Thiếu quy tắc chặn trong khối `server` ở file được include (vd: `conf.d/default.conf`).
  - 13. Thiếu quy tắc ở nhiều khối `server` trong cùng một file cấu hình.
  - 14. Thiếu quy tắc ở nhiều khối `server` trải dài trên nhiều file khác nhau.
  - 15. Có khối `location` chặn nhưng dùng exact match `= /.` thay vì regex `~ /\. `.

- **Không hợp lệ - Cấu hình sai logic (Invalid Logic) - 10 Test Cases:**
  - 16. Có `location ~ /\. ` nhưng bên trong là `allow all;` thay vì `deny all;` -> Báo lỗi.
  - 17. Có `location ~ /\. ` nhưng block rỗng -> Báo lỗi.
  - 18. Có `location ~ /\. ` chỉ chứa `return 404;` nhưng thiếu `deny all;` -> Báo lỗi.
  - 19. Có ngoại lệ `location ^~ /.well-known/acme-challenge/` nhưng thiếu khối `location ~ /\. `.
  - 20. Quy tắc `acme-challenge` nằm _sau_ quy tắc `~ /\. ` (Sai thứ tự ưu tiên của Regex).
  - 21. Quy tắc chặn chỉ nhắm cụ thể vào `location ~ /\.git` chứ không chặn toàn bộ file ẩn.
  - 22. Quy tắc chặn chỉ nhắm cụ thể vào `location ~ /\.env`.
  - 23. Chỉ thị `deny` có đối số sai (vd: `deny 192.168.1.1` thay vì `deny all`).
  - 24. Khối `location ~ /\. ` nằm lồng bên trong một khối `location` khác (có thể không hoạt động như mong muốn trên toàn cục).
  - 25. Chỉ thị `deny all;` tồn tại nhưng bị comment ra (AST bỏ qua) -> Coi như thiếu -> Báo lỗi.

- **Xử lý Đa ngữ cảnh & Hành động Remediation (Context & Actions) - 12 Test Cases:**
  - 26. Kiểm tra thuộc tính `action` là `add` khi thiếu khối `location ~ /\. `.
  - 27. Kiểm tra `logical_context` của hành động `add` là `['http', 'server']`.
  - 28. Kiểm tra `exact_path` trỏ chính xác vào mảng `block` của khối `server` bị thiếu.
  - 29. Payload `remediations` khi `add` phải bao gồm 2 khối `location`: một cho ngoại lệ Let's Encrypt và một để chặn file ẩn.
  - 30. Kiểm tra cấu trúc JSON của khối `location` được `add` hợp lệ (chứa `directive`, `args`, `block`).
  - 31. Xác minh payload trả về khớp hoàn toàn cấu trúc mẫu của `scan_result.json`.
  - 32. Kiểm tra `exact_path` tính toán đúng khi khối `server` đã có sẵn nhiều `location` trước đó.
  - 33. Kiểm tra `exact_path` tính toán đúng khi chèn vào `block` `server` rỗng.
  - 34. Kiểm tra việc gộp lỗi (`_group_by_file`) khi một file có 3 khối `server` đều thiếu quy tắc.
  - 35. Kiểm tra việc gộp lỗi khi nhiều file include đều vi phạm.
  - 36. Đảm bảo không tạo remediation trùng lặp cho cùng một khối `server`.
  - 37. Kiểm tra `action` là `replace` hoặc `add` riêng `deny all;` nếu khối `location ~ /\. ` đã tồn tại nhưng bên trong bị sai logic.

- **Cấu hình Đa tệp & Ngoại lệ (Multi-file & Edge cases) - 5 Test Cases:**
  - 38. Khối `server` nằm trong file include sâu (`conf.d/sub/app.conf`) vi phạm -> `exact_path` và file mapping chuẩn xác.
  - 39. Khối `server` trong `nginx.conf` vi phạm, khối `server` trong `api.conf` hợp lệ -> Chỉ báo lỗi ở file `nginx.conf`.
  - 40. Bỏ qua các khối của module bên thứ ba nếu có tên hoặc cấu trúc tương tự nhưng không phải cấu trúc web tiêu chuẩn.
  - 41. Xử lý khi giá trị chuỗi của đối số location có bọc ngoặc kép (vd: `location "~" "/\."`).
  - 42. Đảm bảo không bị crash khi cấu trúc AST bị khuyết thiếu `block` ở các cấp độ cha.
