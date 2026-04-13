# Tài liệu Kiểm thử: CIS Benchmark 2.4.2 (Detector 242)

**Mục tiêu:** Đảm bảo NGINX từ chối các yêu cầu (requests) dành cho các tên miền (hostnames) không xác định bằng cách cấu hình một khối máy chủ (server block) mặc định ("catch-all").

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector242` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa cụm từ khóa `"unknown host names"`.
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()` (hoặc logic kiểm tra khối Catch-All): Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ có chứa khối `server` mặc định đóng vai trò "catch-all" để từ chối các yêu cầu không hợp lệ. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Trả về mã lỗi 444 (5 test cases):** Khối `server` có `listen 80 default_server;` (hoặc định dạng IP cụ thể) và `return 444;`, ở các vị trí, định dạng block khác nhau.
- **Trả về mã lỗi 4xx khác (4 test cases):** Khối `server` có `default_server` kết hợp `return 400;`, `return 401;`, `return 403;`, hoặc `return 404;`.
- **Hỗ trợ HTTPS/TLS (5 test cases):** Khối `server` có `listen 443 ssl default_server;` với `ssl_reject_handshake on;` (kiểm tra các biến thể IPv4, IPv6, và kèm theo http2/quic).
- **Cấu hình kết hợp cả HTTP và HTTPS (4 test cases):** Khối `server` chứa các chỉ thị `listen` cho cả IPv4/IPv6 cho HTTP và HTTPS, và xử lý chặn đúng cách trong cùng một khối.
- **Nhiều tham số trong listen (4 test cases):** `listen 80 default_server deferred;`, `listen [::]:80 default_server ipv6only=on;`, `listen 443 ssl default_server backlog=512;`. Hệ thống vẫn phải nhận diện đúng tham số `default_server`.
- **Khối catch-all hợp lệ nằm ở file cấu hình khác (2 test cases):** Khối cấu hình hợp lệ nằm trong thư mục `conf.d/` hoặc được khai báo thông qua file `include`.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 15 Test Cases
Kiểm tra các cấu hình thiếu sót hoặc sai lệch dẫn đến việc NGINX không từ chối các hostname không xác định. Hàm kiểm tra phải phát hiện lỗi và đưa ra đối tượng khắc phục.
- **Không có default_server (3 test cases):** Hoàn toàn không có tham số `default_server` ở bất kỳ khối `server` nào (dành cho IPv4, IPv6, và SSL).
- **Có default_server nhưng không chặn (4 test cases):** Có `listen ... default_server;` nhưng lại trả về `return 200;`, phục vụ nội dung tĩnh (`root /var/www/html`), dùng `proxy_pass`, hoặc khối `server` trống trơn.
- **Có default_server với mã lỗi không hợp lệ (2 test cases):** Khối `server` sử dụng `return 500;`, hoặc `return 301;` (chuyển hướng thay vì chặn, tạo lỗ hổng).
- **Thiếu ssl_reject_handshake cho HTTPS (2 test cases):** Có `listen 443 ssl default_server;` nhưng thiếu chỉ thị chặn HTTPS (`ssl_reject_handshake`) hoặc được set là `off`.
- **Kiểm tra cấu trúc dữ liệu phản hồi (4 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình HTTP chính hoặc file cần chỉnh sửa.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"add"` hoặc `"modify"` để thêm khối catch-all.
  - **`directive`:** Mục tiêu là `"server"`.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST (từ `crossplane`), quét toàn bộ ngữ cảnh NGINX để tìm kiếm cấu hình "catch-all".
- **Cấu hình an toàn đầy đủ (4 test cases):**
  - File cấu hình tổng hợp có chứa một khối `server` mặc định chuẩn chỉ cho cả HTTP và HTTPS.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Chỉ có các server block thông thường (4 test cases):** Các khối `server` đều có `server_name` cụ thể và không có `default_server`. Hệ thống phải báo cáo vi phạm mức toàn cục (global/http level) để yêu cầu thêm khối catch-all.
- **Gom nhóm lỗi (Grouping) (2 test cases):** Nếu có nhiều file include mà không file nào chứa cấu hình catch-all, hệ thống phải báo cáo gọn gàng, tránh cảnh báo trùng lặp.
- **Khối catch-all bị comment hoặc vô hiệu hóa (3 test cases):** Hàm `scan()` chỉ phân tích các AST node hợp lệ, nếu khối catch-all bị comment (`#`), hệ thống phải phát hiện thiếu sót và cảnh báo.
- **Hỗn hợp HTTP và HTTPS (3 test cases):** Hệ thống quét thấy có `default_server` từ chối kết nối cho port 80 nhưng thiếu `default_server` cho port 443 (SSL). Cảnh báo cần được tạo ra chỉ cho phần HTTPS bị thiếu.
- **Tính toàn vẹn của kết quả Schema (4 test cases):** Xác nhận lại đối tượng kết quả `scan()` phải chứa đầy đủ các khoá dữ liệu yêu cầu: `file`, `remediations` (chứa `action`, `directive`, `context`) hỗ trợ tự động thêm khối `server` vào cuối khối `http` thông qua auto-remediation.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector242` được thiết kế chặt chẽ nhằm đảm bảo mọi luồng logic quan trọng đều được kiểm chứng:
- **Tổng số lượng test cases:** **63 test cases**
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Các bài kiểm tra đảm bảo hệ thống không chỉ kiểm tra sự tồn tại của tham số `default_server` mà còn phân tích sâu vào hành vi của khối đó (có thực sự từ chối kết nối bằng `return 4xx`, `return 444` hoặc `ssl_reject_handshake` hay không). Điều này đáp ứng chính xác và nghiêm ngặt yêu cầu của CIS Benchmark 2.4.2 và sẵn sàng tích hợp vào công cụ quét NGINX cốt lõi.