# Tài liệu Kiểm thử: Detector 511 (CIS Nginx Benchmark - Recommendation 5.1.1)

## Tổng quan về Recommendation 5.1.1 trong CIS Nginx Benchmark:

Đảm bảo các bộ lọc allow và deny giới hạn truy cập từ các địa chỉ IP cụ thể.
Kiểm soát truy cập dựa trên địa chỉ IP là cơ chế bảo mật chuyên sâu cơ bản. Bằng cách sử dụng các chỉ thị `allow` và `deny`, quyền truy cập vào các block `server` hoặc `location` cụ thể có thể được giới hạn ở các mạng đáng tin cậy, đặc biệt hiệu quả để bảo vệ giao diện quản trị nội bộ.

## Tổng quan về Detector 511

### Mục tiêu của Detector 511

Kiểm tra sự tồn tại và tính đúng đắn của các bộ lọc địa chỉ IP (`allow` và `deny`) trong cấu hình NGINX. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Đầu ra là danh sách các `uncompliances` (JSON). Nếu phát hiện cấu hình `allow` mà thiếu `deny all;` ở cuối, sử dụng sai thứ tự, hoặc lạm dụng `allow all;`, detector sẽ trả về lỗi kèm theo hành động tương ứng (`add`, `delete` hoặc `replace`) để module Auto-Remediation có thể tự động khắc phục.

### Cách hoạt động của Detector 511 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng hàm `traverse_directive` để duyệt đệ quy qua các khối `http`, `server`, và `location`. Tại mỗi khối, detector kiểm tra danh sách các chỉ thị:
- Nếu phát hiện chỉ thị `allow`, phải có chỉ thị `deny all;` nằm ở vị trí sau các chỉ thị `allow` trong cùng một khối ngữ cảnh.
- Cảnh báo và đánh dấu vi phạm nếu sử dụng `allow all;` (vi phạm nguyên tắc đặc quyền tối thiểu).
- Phân tích tính kế thừa giữa các khối (VD: khối con ghi đè khối cha nhưng lại quên chốt bằng `deny all;`).
Nếu phát hiện vi phạm, detector sẽ ghi nhận vị trí bằng `exact_path` và tạo payload hướng dẫn cách sửa cấu hình (như thêm `deny all;` vào cuối khối). Cuối cùng, sử dụng `_group_by_file` để gộp các vi phạm theo từng tệp cấu hình.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_511.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra việc phát hiện lỗi allow/deny IP      |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector511` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"5.1.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Đảm bảo các bộ lọc allow và deny giới hạn truy cập từ các địa chỉ IP cụ thể"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình allow/deny (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Hợp lệ - Có cấu hình allow/deny chuẩn (Valid IP Filtering) - 5 Test Cases:**
  1. Có `allow [IP];` và theo sau là `deny all;` trong cùng một khối `location`.
  2. Có nhiều chỉ thị `allow` (IPv4, IPv6, mạng CIDR) và kết thúc bằng `deny all;`.
  3. Cấu hình `allow` và `deny all;` hợp lệ ở cấp độ khối `server` (bảo vệ toàn bộ server).
  4. Cấu hình `allow` và `deny all;` hợp lệ ở cấp độ khối `http` (áp dụng toàn cục cho mọi server).
  5. Có nhiều khối `location`, trong đó các location nhạy cảm (vd: `/admin`, `/api`) đều được bảo vệ đầy đủ bởi `allow` và `deny all;`.

- **Không hợp lệ - Cấu hình thiếu an toàn (Misconfigured/Missing deny all) - 10 Test Cases:**
  6. Hoàn toàn không có chỉ thị `allow` hay `deny` nào trong toàn bộ cấu hình Nginx (mặc định mở toang).
  7. Có các chỉ thị `allow` nhưng lại thiếu chốt chặn `deny all;` ở cuối khối.
  8. Chỉ thị `deny all;` được đặt TRƯỚC `allow` (Nginx xử lý theo thứ tự từ trên xuống, cấu hình này sẽ chặn toàn bộ truy cập).
  9. Có `allow` nhưng chỉ dùng `deny [IP_khác];` cụ thể mà không có `deny all;`.
  10. Sử dụng chỉ thị `allow all;` (vi phạm nguyên tắc đặc quyền tối thiểu).
  11. Có `deny all;` nhưng nằm ở khác block so với `allow` và không được kế thừa đúng cách làm vô hiệu hóa cấu hình.
  12. Có cấu hình location nhạy cảm (`/admin`) nhưng không hề có giới hạn IP nào.
  13. Chỉ thị `allow` không có tham số (thiếu IP) làm lỗi cú pháp Nginx, kiểm tra cách cây AST bắt lỗi.
  14. Chỉ thị `deny all;` bị comment đi (Crossplane bỏ qua dẫn đến bị coi là thiếu).
  15. Cấu hình `allow` / `deny all;` cấp độ `http` nhưng bị `allow all;` ghi đè hoàn toàn ở cấp độ `server`.

- **Kiểm tra theo cấp độ (Block Levels: http, server, location) - 10 Test Cases:**
  16. `allow`/`deny` định nghĩa ở `http`, không bị khối con nào ghi đè -> Hợp lệ toàn cục.
  17. `allow`/`deny` ở `http`, nhưng bị `allow all;` ở một khối `server` ghi đè -> Không hợp lệ tại `server` đó.
  18. `allow`/`deny` ở `server`, không bị khối `location` con ghi đè -> Hợp lệ.
  19. `allow`/`deny` ở `server`, nhưng bị `allow all;` ở khối `location` ghi đè -> Không hợp lệ tại `location`.
  20. Không có giới hạn ở `http` và `server`, chỉ cấu hình đúng ở một `location` duy nhất -> Hợp lệ cho riêng location đó.
  21. Location lồng nhau (nested location): location cha có `allow`/`deny all;`, location con không khai báo lại (được kế thừa) -> Hợp lệ.
  22. Location lồng nhau: location cha có `allow`/`deny all;`, location con lại khai báo `allow all;` -> Không hợp lệ tại location con.
  23. Nhiều `server` block: một server cấu hình allow/deny đúng chuẩn, một server khác mở toang -> Vi phạm ở server mở toang.
  24. Ghi đè chỉ thị `allow` ở scope nhỏ hơn nhưng quên chốt bằng `deny all;` -> Không hợp lệ do mất deny all của scope cha.
  25. Ghi đè `deny all;` bằng một địa chỉ IP cụ thể ở scope nhỏ hơn (vd: `deny 192.168.1.1;`) -> Không hợp lệ vì thiếu chốt chặn deny all.

- **Cấu hình đa tệp (Multi-file configurations) - 10 Test Cases:**
  26. `nginx.conf` có `allow`/`deny all;`, các file `conf.d/*.conf` kế thừa bình thường -> Hợp lệ.
  27. `nginx.conf` mở, nhưng tất cả các file cấu hình server trong `conf.d/*.conf` đều bảo vệ nghiêm ngặt bằng allow/deny -> Hợp lệ.
  28. `nginx.conf` rỗng, `conf.d/admin.conf` cấu hình đúng, nhưng `conf.d/web.conf` lạm dụng `allow all;` -> Vi phạm hiển thị ở `web.conf`.
  29. Chỉ thị `allow` nằm ở file chính, `deny all;` nằm ở file phụ (trong cùng block thông qua lệnh include) -> Hợp lệ.
  30. Chỉ thị `allow` nằm ở file phụ, nhưng thiếu `deny all;` -> Vi phạm hiển thị tại file phụ.
  31. File chính include file danh sách IP (chứa lệnh `allow [IP]`) nhưng quên không có `deny all;` đi kèm ở cuối.
  32. File `conf.d/default.conf` chứa `allow all;` ở cấp `server` làm lây nhiễm rủi ro.
  33. Một block `server` trải dài qua nhiều file include có tổng hợp đủ cấu hình `allow`/`deny all;` -> Hợp lệ.
  34. Dùng `include` gọi tệp chứa `deny all;` nhưng tệp đó không tồn tại (AST rỗng phần includes) -> Không hợp lệ.
  35. Cấu hình IP whitelist quản lý trong file riêng và được `include` đúng cách ngay trước `deny all;` -> Hợp lệ.

- **Cấu trúc AST, Remediation Payload & Edge Cases - 7 Test Cases:**
  36. Cấu trúc AST thiếu trường `args` trong chỉ thị `deny` -> Báo lỗi.
  37. Khối `limit_except` bên trong `location` sử dụng `allow` và `deny all;` hợp lệ -> Hợp lệ.
  38. Khối `limit_except` có `allow` mà thiếu `deny all;` -> Không hợp lệ.
  39. Đảm bảo payload sinh ra hành động `add` để chèn `deny all;` vào vị trí cuối cùng của khối khi bị thiếu.
  40. Đảm bảo payload sinh ra hành động `delete` để loại bỏ hoàn toàn chỉ thị `allow all;`.
  41. Đảm bảo payload sinh ra hành động chỉnh sửa/chuyển vị trí của `deny all;` xuống dưới cùng nếu nó bị đặt trước `allow`.
  42. Kiểm tra `exact_path` của payload trỏ chính xác đến vị trí mảng (array index) cần thao tác để phục vụ an toàn cho Auto-Remediation.