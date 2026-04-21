# Tài liệu Kiểm thử: Detector 241 (CIS Nginx Benchmark - Recommendation 2.4.1)

## Tổng quan về Recommendation 2.4.1 trong CIS Nginx Benchmark:

Đảm bảo NGINX chỉ lắng nghe các kết nối mạng trên các cổng được ủy quyền. Việc giới hạn các cổng lắng nghe (như 80, 443 TCP và 443 UDP cho HTTP/3) giúp giảm bề mặt tấn công. Vô hiệu hóa các cổng không sử dụng giảm rủi ro truy cập trái phép.

## Tổng quan về Detector 241

### Mục tiêu của Detector 241

Kiểm tra các chỉ thị `listen` trong các khối `server` để đảm bảo chúng chỉ cấu hình NGINX lắng nghe trên danh sách cổng được ủy quyền: `[80, 443, 8080, 8443, 9000]`. Đầu vào là AST cấu hình NGINX (JSON). Đầu ra là danh sách uncompliances (JSON) chỉ rõ file, dòng và tham số `listen` vi phạm.

### Cách hoạt động của Detector 241 dựa trên BaseRecom

Detector 241 kế thừa `BaseRecom`. Hàm `scan()` duyệt qua `parser_output` JSON (chỉ các file `.conf`), dùng `traverse_directive("listen", ...)` để tìm tất cả các chỉ thị `listen`. Với mỗi chỉ thị, tách lấy thông tin cổng (port) từ tham số đầu tiên (xử lý IP:port, [IPv6]:port). Đối chiếu cổng với danh sách hợp lệ `[80, 443, 8080, 8443, 9000]`. Nếu cổng không thuộc danh sách, ghi nhận uncompliance kèm đường dẫn, vị trí dòng, exact path và tạo JSON trả về gom nhóm theo file `_group_by_file()`.

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

Kiểm tra thông tin siêu dữ liệu class `Detector241` theo chuẩn CIS.

- **ID (1 test case):** Đảm bảo ID = `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề = `"Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền"`.
- **Thuộc tính bắt buộc (1 test case):** Có đủ `description`, `audit_procedure`, `impact`, `remediation` cho UI.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

#### Nhóm 1: Cổng hợp lệ cơ bản (Authorized Ports) - 10 Test Cases

Kiểm tra cấu hình dùng cổng trong danh sách cho phép `[80, 443, 8080, 8443, 9000]`. Expect: pass (0 uncompliances).

- `listen 80;` hợp lệ.
- `listen 443;` hợp lệ.
- `listen 8080;` hợp lệ.
- `listen 8443;` hợp lệ.
- `listen 9000;` hợp lệ.
- `listen 443 ssl;` hợp lệ.
- `listen 443 quic reuseport;` hợp lệ (UDP).
- `listen 80;` và `listen 443;` cùng một server block.
- IPv6 cổng hợp lệ: `listen [::]:80;`.
- IPv4 cụ thể cổng hợp lệ: `listen 192.168.1.100:443;`.

#### Nhóm 2: Cổng không hợp lệ (Unauthorized Ports) - 10 Test Cases

Kiểm tra cấu hình dùng cổng ngoài danh sách. Expect: phát hiện uncompliances.

- `listen 81;` không hợp lệ.
- `listen 8081;` không hợp lệ.
- `listen 22;` không hợp lệ.
- `listen 21;` không hợp lệ.
- `listen 4444;` không hợp lệ.
- `listen 6379;` không hợp lệ.
- Trộn lẫn: `listen 80;` và `listen 8081;` chung server block -> Báo lỗi dòng chứa 8081.
- IPv6 không hợp lệ: `listen [::]:81;`.
- IPv4 cụ thể không hợp lệ: `listen 10.0.0.1:22;`.
- Port ngầm định (ví dụ `listen localhost:8081;`) không hợp lệ.

#### Nhóm 3: Tham số phức tạp và cú pháp (Complex Arguments) - 10 Test Cases

Kiểm tra xử lý chuỗi tham số listen phức tạp, socket, IPv6.

- Unix domain socket: `listen unix:/var/run/nginx.sock;` -> Bỏ qua hoặc hợp lệ vì không phải port mạng.
- Nhiều cờ: `listen 80 default_server proxy_protocol;` -> Hợp lệ, trích xuất port 80 chuẩn xác.
- Nhiều cờ ssl: `listen 443 ssl http2 default_server;` -> Hợp lệ.
- Bind flag: `listen 8080 bind;` -> Hợp lệ.
- Cấu hình IP không port: `listen 127.0.0.1;` -> Ngầm định port 80 -> Hợp lệ.
- Cấu hình IPv6 không port: `listen [::1];` -> Ngầm định port 80 -> Hợp lệ.
- Biến: `listen $port;` -> Cảnh báo hoặc báo lỗi vì port động không an toàn/không đánh giá tĩnh được.
- Port vượt quá 65535: `listen 99999;` -> Không hợp lệ.
- Port số 0: `listen 0;` -> Không hợp lệ.
- Không có arg: `listen;` -> Dữ liệu JSON lỗi từ parser, handle an toàn (báo lỗi).

#### Nhóm 4: Nhiều file, cấu trúc lồng nhau (Multiple Files/Blocks) - 12 Test Cases

Kiểm tra khả năng duyệt đệ quy `crossplane` AST, gom nhóm lỗi theo file.

- Nhiều `server` block trong một file: 1 block đúng (80), 1 block sai (81) -> Ghi nhận lỗi ở block sai.
- Main file đúng, included file sai `conf.d/bad.conf` (port 22) -> Báo lỗi trong `bad.conf`.
- Main file sai, included file sai -> Tạo JSON output gồm 2 file riêng biệt bằng `_group_by_file()`.
- Nhiều chỉ thị `listen` sai rải rác ở 3 file `conf.d/*.conf`.
- `server` block đặt ngoài `http` (lỗi cú pháp nhưng test độ cứng parser/detector).
- Chỉ thị `listen 8081;` bị comment (crossplane thường loại, JSON không chứa `listen`) -> Hợp lệ (0 uncompliances).
- Bỏ qua file không phải `.conf`: `bad.txt` chứa `listen 22;` -> Không scan, pass.
- Bỏ qua file backup: `nginx.conf.bak` chứa `listen 22;` -> Không scan, pass.
- Server block trống, không có `listen` ngầm định port 80 -> Hợp lệ.
- Cấu hình rỗng toàn bộ AST -> Hợp lệ.
- Hai lỗi cùng block: `listen 81; listen 82;` -> 2 remediations trong 1 file entry.
- File có 5 server block, mỗi block một port sai -> 5 remediations, gom vào đúng 1 file path.
