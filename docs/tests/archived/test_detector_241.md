# Tài liệu Kiểm thử: CIS Benchmark 2.4.1 (Detector 241)

**Mục tiêu:** Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng (port) được ủy quyền. Theo yêu cầu cụ thể của hệ thống, danh sách các cổng được phép (authorized ports) được giới hạn chặt chẽ ở: `[80, 443, 8080, 3000]`. Hệ thống sử dụng thư viện `crossplane` để phân tích đệ quy cấu hình NGINX, trích xuất tất cả các chỉ thị `listen` và đối chiếu với danh sách cổng được phép. Việc này nhằm thu hẹp bề mặt tấn công (attack surface), ngăn chặn NGINX vô tình mở các dịch vụ ẩn hoặc sử dụng sai giao thức.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector241` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa nội dung liên quan đến việc chỉ lắng nghe trên các cổng được ủy quyền (`"Ensure NGINX only listens for network connections on authorized ports"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các khối `server` có chỉ thị `listen` tuân thủ nghiêm ngặt danh sách `authorized_ports = [80, 443, 8080, 3000]`. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Chỉ lắng nghe trên cổng 80 (HTTP) (5 test cases):** Các cấu hình như `listen 80;`, `listen 127.0.0.1:80;`, `listen [::]:80;`, `listen 80 default_server;`.
- **Chỉ lắng nghe trên cổng 443 (HTTPS/QUIC) (5 test cases):** Các cấu hình `listen 443 ssl;`, `listen 443 ssl http2;`, `listen 443 quic reuseport;` (UDP cho HTTP/3), `listen [::]:443 ssl;`.
- **Lắng nghe trên các cổng ứng dụng 8080 và 3000 (5 test cases):** Các ứng dụng Node.js/Backend nội bộ chạy qua proxy như `listen 8080;`, `listen 0.0.0.0:3000;`, `listen 3000 ssl;`.
- **Nhiều cổng hợp lệ trong cùng một block (4 test cases):** Khối `server` chứa đồng thời `listen 80;` và `listen 443 ssl;` hoặc kết hợp `listen 8080;` và `listen 3000;`.
- **Xử lý các tham số đi kèm phức tạp nhưng cổng hợp lệ (5 test cases):** `listen 443 ssl proxy_protocol;`, `listen 80 deferred;`, `listen 3000 bind;`. Hệ thống cần parse chính xác số cổng bỏ qua các tham số phụ.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình mở cổng nằm ngoài danh sách ủy quyền, kích hoạt cảnh báo vi phạm để chuyển dữ liệu JSON Contract cho module Auto-Remediation (Thành viên 2).
- **Sử dụng các cổng HTTP/HTTPS thay thế không được phép (5 test cases):** Lắng nghe trên các cổng `8000`, `8443`, `8888`.
- **Lắng nghe trên các cổng dịch vụ hệ thống rủi ro cao (5 test cases):** Vô tình cấu hình `listen 21;` (FTP), `listen 22;` (SSH), `listen 25;` (SMTP), `listen 3306;` (MySQL).
- **Lắng nghe trên các cổng ngẫu nhiên/cao (4 test cases):** Cấu hình sử dụng các port như `50000`, `65535` hoặc các port dành cho testing không được dọn dẹp.
- **Trộn lẫn cổng hợp lệ và không hợp lệ (2 test cases):** Khối `server` chứa cả `listen 80;` (hợp lệ) và `listen 8081;` (không hợp lệ). Hệ thống phải chỉ đích danh chỉ thị `listen 8081;` bị vi phạm.
- **Kiểm tra cấu trúc dữ liệu phản hồi JSON (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình NGINX chứa lỗi.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục ưu tiên là `"delete"` (xóa dòng listen vi phạm) hoặc `"comment"` (comment-out dòng vi phạm).
  - **`directive`:** Mục tiêu là chỉ thị `"listen"`.
  - **`context`:** Phải chứa đối tượng định vị chính xác vị trí dòng lệnh trong AST để công cụ diff/Dry-Run có thể hoạt động chính xác.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy từ `crossplane` trên nhiều tệp cấu hình.
- **Cấu hình an toàn trên toàn bộ hệ thống (3 test cases):**
  - Hệ thống bao gồm nhiều file `conf.d/*.conf`, tất cả đều chỉ dùng các cổng 80, 443, 8080, 3000.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Phát hiện vi phạm cổng rải rác (3 test cases):** Quét qua cấu trúc thư mục, phát hiện một file `admin.conf` mở port 9090 và một file `test.conf` mở port 8000. Cần gom nhóm và trả về đúng danh sách lỗi tương ứng với từng file.
- **Gom nhóm lỗi (Grouping) trong một file (3 test cases):** Nếu một file có nhiều block `server` mở port sai, báo cáo phải liệt kê chính xác từng block mà không ghi đè dữ liệu.
- **Xử lý các ngoại lệ khi parse port (3 test cases):** Xử lý an toàn khi chỉ thị `listen` không chứa port (ví dụ NGINX mặc định port 80 nếu chỉ viết `listen localhost;`) hoặc lắng nghe qua `unix:/var/run/nginx.sock` (bỏ qua hoặc xử lý theo rule riêng biệt, không crash logic parse số nguyên).
- **Tương tác với Include Directive phức tạp (5 test cases):** Sử dụng đệ quy `crossplane` để phân tích các file lồng nhau (ví dụ: `nginx.conf` -> `include sites-enabled/*` -> `include snippets/listen.conf`). Scanner phải tìm ra cổng sai ẩn sâu trong `snippets/listen.conf` và chỉ định file đó cần sửa.
- **Tính toàn vẹn của kết quả Schema (3 test cases):** JSON Contract trả về từ Scanner (Thành viên 1) phải chứa đầy đủ thông tin dòng, cột, và file gốc để Auto-Remediation (Thành viên 2) thực hiện Dry-Run tạo Code Diff, và áp dụng qua SSH an toàn (`nginx -t` trước khi ghi đè).

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector241` được thiết kế chặt chẽ nhằm bảo vệ máy chủ khỏi việc rò rỉ dịch vụ nội bộ và đáp ứng đúng tiêu chí đánh giá của đồ án:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Việc kiểm soát các chỉ thị `listen` có thể phức tạp do cú pháp linh hoạt của NGINX (IP:Port, IPv6, kèm các cờ như `ssl`, `http2`, `quic`). Logic trong module Backend phải bóc tách chuỗi regex hiệu quả để lấy ra giá trị port dạng số (integer). Sự chính xác ở khâu này quyết định việc Thành viên 2 có thể tự động comment-out dòng vi phạm một cách an toàn mà không làm sập cấu hình NGINX, đóng góp trực tiếp vào mục tiêu Zero-Downtime của luồng Safe Remediation trong báo cáo tốt nghiệp.
