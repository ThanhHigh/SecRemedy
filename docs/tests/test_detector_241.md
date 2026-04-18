# Tài liệu Kiểm thử: Detector 241 (CIS Nginx Benchmark - Recommendation 2.4.1)

## Tổng quan về Recommendation 2.4.1 trong CIS Nginx Benchmark:

NGINX chỉ nên được cấu hình để lắng nghe (listen) trên các cổng (ports) và giao thức được phép. Mặc dù các cấu hình truyền thống dùng HTTP/1.1 và HTTP/2 sử dụng TCP port 80 và 443, modern HTTP/3 (QUIC) tận dụng UDP port 443. Đảm bảo rằng NGINX chỉ kết nối vào các network interfaces và ports được phê duyệt giúp giảm thiểu đáng kể bề mặt tấn công.

## Tổng quan về Detector 241

### Mục tiêu của Detector 241

Mục tiêu của Detector 241 là tự động phân tích cấu trúc AST của file cấu hình NGINX, tìm kiếm tất cả các chỉ thị `listen` và trích xuất cổng mạng (port) đang được cấu hình. Nếu phát hiện cổng này không nằm trong danh sách các cổng được hệ thống phê duyệt (mặc định: `80`, `443`, `8080`, `3000`), detector sẽ ghi nhận đây là cấu hình không tuân thủ (uncompliance) và trả về dữ liệu chuẩn JSON Contract có chứa thông tin dòng lệnh cần bị xóa (action: `delete`) để module Auto-Remediation có thể can thiệp an toàn.

### Cách hoạt động của Detector 241 dựa trên BaseRecom

Detector 241 kế thừa lớp `BaseRecom` và cài đè phương thức `evaluate(...)`. 
- Hàm sử dụng helper `_extract_port(...)` để phân giải linh hoạt tham số của chỉ thị `listen`, giúp trích xuất chuẩn xác port bất chấp định dạng là địa chỉ IPv4 (vd: `127.0.0.1:8080`), IPv6 (vd: `[::]:443`), số port trơn (`80`), hay Unix socket (bỏ qua).
- Nếu directive hiện tại là `server`, detector sẽ lặp qua các lệnh bên trong. Khi gặp `listen`, nó sẽ kiểm tra cổng. 
- Nếu cổng trích xuất được KHÔNG thuộc danh sách được phép (`self.authorized_ports`), detector tạo ra một đề xuất khắc phục chứa: `action: "delete"`, `exact_path` (đường dẫn AST tuyệt đối) và `logical_context`, hỗ trợ tốt cho Dry-Run diff.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_241.py):

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

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector241` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure NGINX only listens for network connections on authorized ports"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), `remediation` (biện pháp khắc phục), `profile` và `authorized_ports` để hiển thị trên Frontend Dashboard và cung cấp logic kiểm duyệt.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **Nhóm 1: Các cấu hình cổng tuân thủ / Hợp lệ (Compliant) (10 Test Cases)**
  - **TC 1:** Lắng nghe trên cổng `80` (VD: `listen 80;`). (Compliant)
  - **TC 2:** Lắng nghe trên cổng `443` (VD: `listen 443 ssl;`). (Compliant)
  - **TC 3:** Lắng nghe trên cổng `8080` (VD: `listen 8080;`). (Compliant)
  - **TC 4:** Lắng nghe trên cổng `3000` (VD: `listen 3000;`). (Compliant)
  - **TC 5:** IPv4 cục bộ kết hợp cổng 80 (VD: `listen 127.0.0.1:80;`). (Compliant)
  - **TC 6:** IPv6 kết hợp cổng 443 (VD: `listen [::]:443 ipv6only=on;`). (Compliant)
  - **TC 7:** IPv6 cục bộ kết hợp cổng 8080 (VD: `listen [::1]:8080;`). (Compliant)
  - **TC 8:** Lắng nghe trên Unix socket (VD: `listen unix:/var/run/nginx.sock;`). Bỏ qua, hợp lệ. (Compliant)
  - **TC 9:** Lắng nghe chỉ localhost dạng text (VD: `listen localhost;`). Bỏ qua, hợp lệ. (Compliant)
  - **TC 10:** Cấu hình có nhiều `server` block, tất cả đều lắng nghe cổng hợp lệ (80, 443). (Compliant)

- **Nhóm 2: Cấu hình cổng vi phạm (Non-compliant - Unauthorized Ports) (12 Test Cases)**
  - **TC 11:** Lắng nghe trên cổng không được phép `8081` (VD: `listen 8081;`). (Non-compliant)
  - **TC 12:** Lắng nghe trên cổng không được phép `8443`. (Non-compliant)
  - **TC 13:** Lắng nghe trên cổng `8888`. (Non-compliant)
  - **TC 14:** Lắng nghe trên cổng cơ sở dữ liệu `3306` (MySQL). (Non-compliant)
  - **TC 15:** Lắng nghe trên cổng `5432` (PostgreSQL). (Non-compliant)
  - **TC 16:** Lắng nghe trên cổng `27017` (MongoDB). (Non-compliant)
  - **TC 17:** Lắng nghe trên cổng `6379` (Redis). (Non-compliant)
  - **TC 18:** Lắng nghe trên cổng `11211` (Memcached). (Non-compliant)
  - **TC 19:** Lắng nghe trên cổng quản trị mặc định `9000`. (Non-compliant)
  - **TC 20:** Lắng nghe trên cổng `8000`. (Non-compliant)
  - **TC 21:** Lắng nghe trên cổng HTTP alternate `8088`. (Non-compliant)
  - **TC 22:** Lắng nghe trên cổng `21` (FTP) qua NGINX stream proxy. (Non-compliant)

- **Nhóm 3: Cấu trúc IP & Cổng vi phạm hỗn hợp (Mixed IP & Port Formatting) (10 Test Cases)**
  - **TC 23:** Cổng vi phạm với IPv4 (VD: `listen 192.168.1.1:8081;`). (Non-compliant)
  - **TC 24:** Cổng vi phạm với IPv6 (VD: `listen [fe80::1]:8443;`). (Non-compliant)
  - **TC 25:** Một `server` block chứa một cổng hợp lệ (`listen 80`) và một cổng vi phạm (`listen 8888`). Chỉ phát hiện vi phạm ở `8888`. (Non-compliant)
  - **TC 26:** Nhiều `server` block trong cùng file: Block 1 hợp lệ (80, 443), Block 2 vi phạm (9090). Chỉ báo lỗi ở cấu trúc Block 2. (Non-compliant)
  - **TC 27:** Cổng vi phạm kèm tham số bổ sung (VD: `listen 8443 ssl http2 default_server;`). (Non-compliant)
  - **TC 28:** Chỉ thị `listen` nằm đơn lẻ ngoài block `server` (VD: ở đầu file được include) khai báo cổng `8888`. (Non-compliant)
  - **TC 29:** Lắng nghe cổng vi phạm kết hợp socket Unix (VD: nhiều dòng listen, 1 dòng `unix:` hợp lệ, 1 dòng `9999` vi phạm). (Non-compliant)
  - **TC 30:** `listen` rỗng tham số (`listen;`), lỗi cú pháp Nginx, đảm bảo detector không crash. (Compliant)
  - **TC 31:** `listen` có tham số lỗi (VD: `listen abc:def;`), không thể trích xuất port, đảm bảo detector không crash. (Compliant)
  - **TC 32:** Cấu hình có rất nhiều server blocks lồng nhau, kiểm tra tính toán chỉ mục AST (exact_path) không bị sai. (Non-compliant)

- **Nhóm 4: JSON Contract Đầu Ra (Output Structure Validation) (10 Test Cases)**
  - **TC 33:** Xác minh JSON Contract có field `action` mang giá trị `"delete"`.
  - **TC 34:** Xác minh JSON Contract có field `directive` mang giá trị `"listen"`.
  - **TC 35:** Xác minh JSON Contract có mảng `exact_path` đầy đủ các chỉ mục trỏ đúng đến thẻ `listen` vi phạm trong cây AST.
  - **TC 36:** Xác minh JSON Contract có `logical_context` chứa `["server"]` (hoặc rỗng nếu ở cấp ngoài cùng).
  - **TC 37:** Xác minh JSON Contract bắt đúng `filepath` của file đang được kiểm tra.
  - **TC 38:** Nếu một file có 2 dòng `listen` vi phạm, mảng `remediations` trả về phải chứa exaclty 2 phần tử độc lập.
  - **TC 39:** Đảm bảo với file hoàn toàn hợp lệ, hàm evaluate / scan trả về kết quả rỗng (không có mảng `remediations`).
  - **TC 40:** Kiểm tra JSON contract không lưu lại raw value nguyên bản của dòng lệnh, mà chỉ dùng đường dẫn logic, đảm bảo tối ưu kích thước payload.
  - **TC 41:** Thực thi kết hợp module quét toàn diện trên giả lập nhiều file config (ví dụ quét toàn bộ `conf.d/` có chứa 3 file vi phạm).
  - **TC 42:** So sánh JSON Contract trả về có tương thích 100% với kỳ vọng đầu vào của module Auto-Remediation (Dry-Run engine).