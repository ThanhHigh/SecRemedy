# Tài liệu Kiểm thử: Detector 411 (CIS Nginx Benchmark - Recommendation 4.1.1)

## Tổng quan về Recommendation 4.1.1 trong CIS Nginx Benchmark:
**Đảm bảo HTTP được chuyển hướng sang HTTPS (Thủ công)**
Các trình duyệt và client thiết lập kết nối mã hóa với server bằng HTTPS. Các yêu cầu không được mã hóa cần được chuyển hướng để chúng được mã hóa, nghĩa là bất kỳ port HTTP nào đang lắng nghe trên web server (ví dụ port 80) đều phải chuyển hướng đến một server profile sử dụng HTTPS. Điều này giúp đảm bảo an toàn cho traffic của người dùng, tăng độ tin cậy của website.

## Tổng quan về Detector 411

### Mục tiêu của Detector 411
Mục tiêu của Detector 411 là quét AST (JSON) sinh bởi Crossplane từ cấu hình Nginx, tìm các khối `server` đang lắng nghe ở các port không mã hóa (ví dụ: port 80) và kiểm tra xem có lệnh chuyển hướng (`return` hoặc `rewrite`) toàn bộ traffic sang HTTPS hay không. Đầu ra là danh sách các vi phạm (uncompliances) chuyển cho module Auto-Remediation xử lý.

### Cách hoạt động của Detector 411 dựa trên BaseRecom
Dựa trên `BaseRecom`, Detector 411 duyệt cây AST, tập trung vào khối `http` và các khối `server`. Nó tìm các chỉ thị `listen` chỉ định port HTTP (như 80, hoặc mặc định không khai báo port). Nếu phát hiện khối `server` phục vụ HTTP, nó sẽ tìm kiếm lệnh `return` (ví dụ: `return 301 https://$host$request_uri;`) hoặc lệnh `rewrite` có chức năng điều hướng giao thức sang `https://`. Nếu khối `server` HTTP không thực hiện chuyển hướng bảo mật này, detector sẽ ghi nhận một lỗi vi phạm (uncompliance) kèm theo vị trí file và dòng tương ứng.

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
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra toàn bộ đường ống                     |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector411` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"4.1.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure HTTP is redirected to HTTPS"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Nhóm 1: Cấu hình tuân thủ (Compliant Configurations) - 8 Test Cases**
  - Khối `server` có `listen 80` và `return 301 https://$host$request_uri;` ở cấp độ thư mục gốc.
  - Khối `server` có `listen 80` và `return 301 https://$server_name$request_uri;`.
  - Khối `server` có `listen [::]:80` (IPv6) và chuyển hướng `return 301 https...`.
  - Khối `server` dùng lệnh `rewrite ^(.*)$ https://$host$1 permanent;`.
  - Chỉ có khối `server` lắng nghe port 443 (`listen 443 ssl;`), không có port 80.
  - Lệnh chuyển hướng nằm trong khối `location /`.
  - File cấu hình chứa nhiều khối `server` HTTP, tất cả đều có lệnh chuyển hướng đúng.
  - Khối `server` lắng nghe port HTTP tùy chỉnh (ví dụ 8080) và có chuyển hướng sang HTTPS.

- **Nhóm 2: Cấu hình không tuân thủ cơ bản (Basic Non-Compliant Configurations) - 10 Test Cases**
  - Khối `server` lắng nghe port 80 nhưng không có lệnh `return` hay `rewrite`.
  - Khối `server` không có chỉ thị `listen` (mặc định lắng nghe port 80) và không chuyển hướng.
  - Có lệnh chuyển hướng nhưng lại trỏ sang HTTP (`return 301 http://$host$request_uri;`).
  - Lệnh `return` thiếu URL đích (`return 301;`).
  - Lệnh `return` trả về mã lỗi thay vì chuyển hướng (`return 404;` hoặc `return 403;`).
  - Lệnh `rewrite` không chuyển URL sang protocol `https://`.
  - Lệnh chuyển hướng có URL đúng nhưng trả về mã không hợp lệ (ngoài 301, 302, 307, 308).
  - Có 2 khối `server`, 1 khối tuân thủ, 1 khối vi phạm (bắt đúng 1 lỗi).
  - Khối `server` HTTP phục vụ trực tiếp nội dung (`root`, `index`) không có chuyển hướng.
  - Chuyển hướng sang một port khác nhưng không ghi rõ protocol `https://`.

- **Nhóm 3: Các biến thể tinh vi của lệnh `return` và `rewrite` (Subtle Variations) - 12 Test Cases**
  - Sử dụng mã 302 (Found) cho lệnh `return` sang HTTPS.
  - Sử dụng mã 307 (Temporary Redirect) cho lệnh `return`.
  - Sử dụng mã 308 (Permanent Redirect) cho lệnh `return`.
  - Lệnh `rewrite` dùng cờ `redirect` (mã 302) thay vì `permanent`.
  - Lệnh `return` trỏ đến một domain HTTPS cụ thể được hardcode (`return 301 https://example.com$request_uri;`).
  - Lệnh `return` URL HTTPS nhưng không ghi rõ mã trạng thái (`return https://$host$request_uri;`).
  - Khối `server` chứa `if ($scheme != "https") { return 301 https://$host$request_uri; }`.
  - Lệnh `return` nằm sâu trong khối `location` lồng nhau.
  - Lệnh `return` viết thiếu tham số nhưng parse AST vẫn nhận nhận dạng (ví dụ khoảng trắng dư thừa).
  - Sử dụng `rewrite` với Regex phức tạp để ép luồng request sang HTTPS.
  - Sử dụng biến tùy chỉnh thay thế `$host` hoặc `$request_uri`.
  - Khối `server` có cả `return 301 https...` và cấu hình web bình thường (được xem là tuân thủ vì `return` sẽ ngắt request sớm).

- **Nhóm 4: Cấu trúc nhiều file và Include (Multi-file & Includes) - 6 Test Cases**
  - Khối `server` vi phạm nằm trong file cấu hình phụ (ví dụ `conf.d/http.conf`).
  - Khối `server` tuân thủ nằm trong file cấu hình phụ.
  - Một project Nginx có nhiều khối `server` port 80 vi phạm phân tán ở nhiều file khác nhau.
  - Lệnh `return` chuyển hướng được nạp vào thông qua chỉ thị `include` (ví dụ `include snippets/redirect.conf;`).
  - Chỉ thị chuyển hướng được cấu hình chung tại cấp độ `http` (áp dụng cho mọi server).
  - Gộp chung nhiều file với các port 80, 8080, 443 trộn lẫn, check đúng đối tượng vi phạm.

- **Nhóm 5: Các trường hợp Edge Cases & Lỗi phân tích (Edge Cases & Parsing anomalies) - 6 Test Cases**
  - Chỉ thị `listen` dùng socket Unix thay vì TCP IP (`listen unix:/var/run/nginx.sock;`) mà không có `return`.
  - Lắng nghe port 80 đi kèm các tham số như `default_server`, `deferred`.
  - Lắng nghe port 80 đi kèm tham số `ssl` (cấu hình mâu thuẫn nhưng vẫn cần parse).
  - File cấu hình thiếu khối `http` (AST rỗng hoặc cấu trúc root cấp cao sai).
  - Chỉ thị `listen` sử dụng biến thay vì số port (nếu cú pháp hợp lệ).
  - Cấu hình Nginx hoàn toàn rỗng.