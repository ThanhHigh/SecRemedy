# Tài liệu Kiểm thử: Detector 32 (CIS Nginx Benchmark - Recommendation 3.2)

## Tổng quan về Recommendation 3.2 trong CIS Nginx Benchmark:

Đảm bảo tính năng ghi log truy cập (access_log) được bật.
Chỉ thị `access_log` cho phép ghi nhận các yêu cầu từ client, cung cấp lịch sử sử dụng hệ thống chi tiết phục vụ điều tra sự cố và kiểm toán. Nếu tắt (`access_log off;`), hệ thống sẽ mù trước các cuộc tấn công web như SQL injection hay Brute Force. Do đó, cần đảm bảo `access_log` không bị tắt ở phạm vi toàn cục (`http`) hoặc trong các khối `server` và `location` xử lý nghiệp vụ chính.

## Tổng quan về Detector 32

### Mục tiêu của Detector 32

Kiểm tra việc sử dụng chỉ thị `access_log off;` trong cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu tìm thấy `access_log off;` ở các vị trí không được phép (như `http`, `server`, hoặc các `location` nghiệp vụ trọng yếu), trả về lỗi kèm hành động `delete` để Auto-Remediation xóa dòng này, từ đó khôi phục lại tính năng ghi log mặc định của NGINX. Cho phép ngoại lệ đối với các tài nguyên tĩnh hoặc không quan trọng (vd: `location = /favicon.ico`).

### Cách hoạt động của Detector 32 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng `traverse_directive` để duyệt qua toàn bộ cây AST tìm các chỉ thị `access_log`. Nếu tham số đầu tiên của `access_log` là `off` (so sánh không phân biệt chữ hoa chữ thường), detector sẽ tiếp tục kiểm tra ngữ cảnh (logical context) của nó. Nếu nằm trong khối `http` hoặc `server`, hoặc khối `location` không thuộc danh sách ngoại lệ được cấu hình sẵn (như `/favicon.ico` hay tài nguyên tĩnh), vi phạm sẽ được ghi nhận. Hệ thống sử dụng `_group_by_file` để gộp vi phạm theo file.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_32.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                              |
| :------------------------------------------------------------------- | :--------------------- | :---------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc  |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện `access_log off;` |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector32` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"3.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Đảm bảo tính năng ghi log truy cập (access_log) được bật"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc phát hiện cấu hình tắt log thông qua JSON AST từ `crossplane`.

- **Hợp lệ - Bật Access Log đúng chuẩn (Valid Configuration) - 10 Test Cases:**
  1. Chỉ thị `access_log` được cấu hình với đường dẫn file hợp lệ trong khối `http`.
  2. Chỉ thị `access_log` được cấu hình với đường dẫn file hợp lệ trong khối `server`.
  3. Chỉ thị `access_log` được cấu hình với đường dẫn file hợp lệ trong khối `location /`.
  4. Không định nghĩa rõ ràng `access_log` (Mặc định Nginx sẽ bật log) -> Hợp lệ.
  5. Cấu hình `access_log` đi kèm định dạng format tùy chỉnh (vd: `main_json`).
  6. `access_log off;` nằm đúng trong khối ngoại lệ: `location = /favicon.ico`.
  7. `access_log off;` nằm đúng trong khối ngoại lệ: `location = /robots.txt`.
  8. `access_log off;` cho các file tĩnh phổ biến: `location ~* \.(css|js|jpg|jpeg|png)$`.
  9. Nhiều chỉ thị `access_log` cùng lúc (ghi ra nhiều file) trong khối `http`.
  10. Kế thừa log: Khối `http` cấu hình đường dẫn file hợp lệ, các `server` con không ghi đè nhưng hợp lệ.

- **Không hợp lệ - Tắt Access Log (access_log off;) - 15 Test Cases:**
  - 11. `access_log off;` được thiết lập ở cấp độ `http` (Tắt toàn cục).
  - 12. `access_log off;` được thiết lập ở cấp độ `server`.
  - 13. `access_log off;` xuất hiện ở cả khối `http` và `server`.
  - 14. Khối `http` không khai báo, nhưng `server` khai báo `access_log off;`.
  - 15. Khối `http` có log hợp lệ, nhưng một khối `server` quan trọng ghi đè `access_log off;`.
  - 16. `access_log off;` trong `location /` (điểm truy cập chính của ứng dụng).
  - 17. `access_log off;` trong `location ~ \.php$` (xử lý logic backend).
  - 18. Có nhiều khối `server`, tất cả đều có `access_log off;`.
  - 19. `access_log off;` trong một khối `location /api/` xử lý API quan trọng.
  - 20. Khối `server` có cấu hình `listen 443 ssl` bị đặt `access_log off;`.
  - 21. `access_log OFF;` (chữ hoa) trong khối `server` (kiểm tra case-insensitive).
  - 22. `access_log "off";` (có dấu nháy) trong khối `http`.
  - 23. `access_log off;` kết hợp với `access_log /path/to/log` trong cùng một khối (Nginx sẽ ưu tiên tắt nếu cấu hình sai).
  - 24. `access_log off` dư thừa tham số (vd: `access_log off main;` - cấu hình lỗi nhưng vẫn cần xử lý bắt vi phạm).
  - 25. `access_log off;` được cấu hình lặp lại nhiều lần trong cùng khối `server`.

- **Cấu hình đa tệp (Multi-file configurations) - 10 Test Cases:**
  - 26. `nginx.conf` bật log, nhưng file `conf.d/app.conf` chứa khối `server` tắt log.
  - 27. File `conf.d/app.conf` chứa khối `server` có log hợp lệ, nhưng `nginx.conf` chứa `access_log off;` ở `http`.
  - 28. Tất cả file trong `conf.d/` đều có `access_log off;` ở cấp độ `server`.
  - 29. Chỉ thị `access_log off;` nằm trong file cấu hình đính kèm qua `include` tại cấp độ `location`.
  - 30. File `nginx.conf` có `access_log off;`, file `conf.d/admin.conf` có `access_log /path/` -> Báo vi phạm ở `nginx.conf`.
  - 31. File được include chứa cấu hình ngoại lệ (vd: `favicon.conf` chứa `access_log off;` cho favicon) -> Hợp lệ.
  - 32. Hai file `conf.d` khác nhau cùng định nghĩa tắt log ở cấp độ `location /`.
  - 33. Khối `server` trong `nginx.conf` include một file chứa `access_log off;`.
  - 34. `access_log off;` nằm trong block phụ `if` (Nginx không khuyến khích nhưng cấu hình vẫn cho phép).
  - 35. File cấu hình chính không có `http`, chỉ trực tiếp cấu hình `server` có `access_log off;`.

- **Kiểm tra Payload Remediation và Ngoại lệ cấu trúc (Remediation & Edge Cases) - 7 Test Cases:**
  - 36. Payload cho `access_log off;` ở `http`: Trả về `action: delete` với `exact_path` tương ứng.
  - 37. Payload cho `access_log off;` ở `server`: Trả về `action: delete` cho directive tắt log.
  - 38. Payload cho nhiều vi phạm tắt log ở các `location` khác nhau: Trả về một mảng chứa nhiều hành động `delete`.
  - 39. Trường hợp cấu hình Nginx bị rỗng hoàn toàn (không có `http`, `server`) -> Trả về pass.
  - 40. Trường hợp `access_log` trỏ tới `/dev/null` (cũng tương đương với việc tắt log) -> Cần được bắt lỗi và trả về payload xóa.
  - 41. Xử lý chính xác index trong `exact_path` khi có nhiều chỉ thị trước `access_log off;`.
  - 42. Đảm bảo hành động `delete` chỉ loại bỏ duy nhất dòng `access_log off;` mà không ảnh hưởng tới các cấu hình log hợp lệ khác (nếu có trong cùng file).
