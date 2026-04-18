# Tài liệu Kiểm thử: Detector 252 (CIS Nginx Benchmark - Recommendation 2.5.2)

## Tổng quan về Recommendation 2.5.2 trong CIS Nginx Benchmark:

**Đảm bảo các trang báo lỗi mặc định và trang index.html không chứa thông tin về NGINX (Manual)**

**Mô tả:** Các trang báo lỗi mặc định (ví dụ: 404, 500) và trang chào mừng mặc định thường chứa nhãn hiệu hoặc chữ ký của NGINX. Các trang này nên được xóa hoặc thay thế bằng các trang có nội dung chung hoặc mang thương hiệu tùy chỉnh để không tiết lộ công nghệ máy chủ bên dưới.

**Lý do (Rationale):** Các trang lỗi tiêu chuẩn của NGINX sẽ nhận dạng trực quan phần mềm máy chủ, ngay cả khi các tiêu đề (headers) đã bị ẩn. Bằng cách thu thập thông tin về ngăn xếp công nghệ bên dưới, những kẻ tấn công có thể tinh chỉnh các khai thác của chúng nhắm vào các lỗ hổng đã biết của NGINX. Thay thế các trang mặc định bằng nội dung chung chung hoặc mang thương hiệu riêng sẽ loại bỏ véc-tơ rò rỉ thông tin này và tăng độ khó cho việc trinh sát thành công.

## Tổng quan về Detector 252

### Mục tiêu của Detector 252

- Mục tiêu của detector 252 là kiểm tra xem cấu hình Nginx có định nghĩa chỉ thị `error_page` để tùy chỉnh trang báo lỗi hay không. Việc sử dụng trang lỗi tùy chỉnh sẽ giúp ẩn đi thông tin máy chủ Nginx mặc định.
- Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane.
- Đầu ra là danh sách các uncompliances (JSON) trỏ đến các vị trí (file, dòng, khối) thiếu chỉ thị `error_page` để chuyển cho module Auto-Remediation.

### Cách hoạt động của Detector 252 dựa trên BaseRecom

Detector 252 kế thừa từ `BaseRecom` và duyệt qua cấu trúc cây AST của Nginx. Detector kiểm tra sự hiện diện của chỉ thị `error_page`. Chỉ thị này có thể nằm ở các ngữ cảnh (context) `http`, `server`, hoặc `location`. Nếu một khối `server` không có `error_page` và cũng không được kế thừa từ khối `http` bao ngoài, khối `server` đó sẽ bị đánh dấu là không tuân thủ (uncompliant).

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_252.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**
- **`_server_block(directives: list) -> dict`**
- **`_http_block(directives: list) -> dict`**
- **`_location_block(args: list, directives: list) -> dict`**
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra toàn bộ đường ống                     |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector252` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure default error and index.html pages do not reference NGINX"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Nhóm 1: Hoàn toàn thiếu `error_page` (10 Test cases):** Kiểm tra các cấu hình (từ cơ bản đến phức tạp, nhiều `server` block) hoàn toàn không định nghĩa `error_page` ở bất kỳ đâu. Tất cả các khối `server` đều phải bị báo cáo là uncompliant.
- **Nhóm 2: Khai báo `error_page` ở cấp độ `http` (10 Test cases):** Kiểm tra các cấu hình có `error_page` ở trong khối `http`. Các khối `server` con sẽ kế thừa cấu hình này và được coi là compliant (tuân thủ).
- **Nhóm 3: Khai báo `error_page` ở cấp độ `server` (10 Test cases):** Kiểm tra cấu hình không có `error_page` ở `http`, nhưng có ở `server`. Đảm bảo các `server` có khai báo thì compliant, các `server` thiếu thì uncompliant.
- **Nhóm 4: Ghi đè và khai báo ở `location` (6 Test cases):** Kiểm tra sự kế thừa và ghi đè của `error_page` từ `http` -> `server` -> `location`.
- **Nhóm 5: Cấu hình phân tán qua `include` (6 Test cases):** Kiểm tra hành vi của detector khi cấu hình được chia thành nhiều file thông qua chỉ thị `include` (ví dụ: khai báo `error_page` ở `nginx.conf` và các khối `server` ở các file cấu hình trong `conf.d/`). Phải đảm bảo tính kế thừa qua các file khác nhau được xử lý đúng.
