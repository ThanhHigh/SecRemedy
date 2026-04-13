# Tài liệu Kiểm thử: CIS Benchmark 2.4.1 (Detector 241)

**Mục tiêu:** Đảm bảo NGINX chỉ lắng nghe (listen) các kết nối mạng trên các cổng (ports) đã được phê duyệt và ủy quyền. Trong hệ thống này, danh sách các cổng được ủy quyền mặc định là: **`authorized_ports = [80, 443, 8080, 3000]`**.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector241` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa cụm từ khóa `"authorized ports"`.
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()` (hoặc logic kiểm tra khối Listen): Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ chỉ chứa các cổng nằm trong danh sách được phép (`[80, 443, 8080, 3000]`). Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Cổng chuẩn HTTP (80) và HTTPS (443) (5 test cases):** Khối `server` có `listen 80;`, `listen 443 ssl;`, `listen [::]:80;`, `listen 127.0.0.1:443 ssl;`, với các tham số bổ sung như `default_server` không gây lỗi.
- **Cổng bổ sung được ủy quyền (8080, 3000) (4 test cases):** Khối `server` có `listen 8080;`, `listen 3000;`, `listen [::]:8080;`, `listen 127.0.0.1:3000;`.
- **Hỗ trợ HTTP/2 và HTTP/3 (QUIC) (5 test cases):** Khối `server` có `listen 443 quic reuseport;` (UDP) hoặc `listen 8080 quic;` hoạt động hợp lệ trên các cổng được ủy quyền.
- **Cấu hình kết hợp nhiều cổng hợp lệ (4 test cases):** Khối `server` chứa các chỉ thị `listen` cho cả 80, 443, 8080, và 3000 trong cùng một block.
- **Nhiều tham số trong listen hợp lệ (4 test cases):** `listen 3000 deferred;`, `listen [::]:8080 ipv6only=on;`, `listen 443 ssl backlog=512;`. Hệ thống vẫn phải nhận diện đúng cổng thuộc danh sách hợp lệ.
- **Các cổng hợp lệ nằm ở file cấu hình khác (2 test cases):** Khối cấu hình hợp lệ nằm trong thư mục `conf.d/` hoặc được khai báo thông qua file `include`.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 20 Test Cases
Kiểm tra các cấu hình chứa cổng không nằm trong danh sách `[80, 443, 8080, 3000]`. Hàm kiểm tra phải phát hiện lỗi và đưa ra đối tượng khắc phục.
- **Lắng nghe trên cổng không được phép (5 test cases):** Lắng nghe trên các cổng nằm ngoài danh sách như `listen 81;`, `listen 8443 ssl;`, `listen 9000;`, `listen 444;`, `listen 5000;`.
- **Cổng không được phép kèm theo IP (5 test cases):** Các cấu hình như `listen 0.0.0.0:8081;`, `listen 192.168.1.100:9090;`, `listen [::1]:8888;`, `listen 10.0.0.5:22;`, `listen 127.0.0.1:27017;`.
- **Trộn lẫn cổng hợp lệ và không hợp lệ (4 test cases):** Khối `server` có cả `listen 80;` và `listen 8081;`, hoặc `listen 3000;` và `listen 4000;`. Hệ thống chỉ đánh dấu lỗi cho các chỉ thị `listen` vi phạm.
- **Giao thức UDP trên cổng không cho phép (2 test cases):** Có `listen 8443 quic;` hoặc listen UDP trên các cổng khác không nằm trong danh sách được ủy quyền.
- **Kiểm tra cấu trúc dữ liệu phản hồi (4 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình chứa cổng sai.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"delete"` hoặc `"replace"` (để loại bỏ hoặc vô hiệu hóa dòng cấu hình sai).
  - **`directive`:** Mục tiêu là `"listen"`.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 15 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST (từ `crossplane`), quét toàn bộ ngữ cảnh NGINX để tìm kiếm cấu hình cổng mở.
- **Cấu hình an toàn đầy đủ (3 test cases):**
  - File cấu hình tổng hợp chỉ chứa các khối `server` sử dụng các cổng thuộc danh sách `[80, 443, 8080, 3000]`.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhiều file cấu hình có cổng vi phạm (3 test cases):** Quét thấy cổng 9090 trong `admin.conf` và 8443 trong `api.conf`. Hệ thống báo cáo đầy đủ các vi phạm ở từng file.
- **Gom nhóm lỗi (Grouping) (3 test cases):** Cùng một file cấu hình có nhiều lỗi `listen` sai cổng (ví dụ: `listen 8081;` và `listen 8082;`), hệ thống gom nhóm lỗi theo file một cách rõ ràng.
- **Cổng không hợp lệ bị comment (3 test cases):** Cấu hình `# listen 9000;` sẽ bị hệ thống AST bỏ qua, không được tính là vi phạm.
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận lại đối tượng kết quả `scan()` phải chứa đầy đủ các khoá dữ liệu yêu cầu: `file`, `remediations` (chứa `action`, `directive`, `context`) hỗ trợ tự động loại bỏ (hoặc comment) dòng `listen` không hợp lệ thông qua auto-remediation.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector241` được thiết kế chặt chẽ nhằm đảm bảo mọi luồng logic quan trọng đều được kiểm chứng:
- **Tổng số lượng test cases:** **63 test cases** (4 + 24 + 20 + 15)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Các bài kiểm tra đảm bảo hệ thống không chỉ kiểm tra cổng trong chỉ thị `listen` mà còn phân tích cấu trúc giá trị (IP:Port, tham số UDP/QUIC) và đối chiếu với danh sách `authorized_ports = [80, 443, 8080, 3000]`. Việc lọc đúng cổng được ủy quyền và xử lý gom nhóm file chuẩn xác giúp công cụ đáp ứng nghiêm ngặt yêu cầu của CIS Benchmark 2.4.1 và sẵn sàng tích hợp vào pipeline tự động hóa.