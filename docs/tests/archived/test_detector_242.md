# Tài liệu Kiểm thử: CIS Benchmark 2.4.2 (Detector 242)

**Mục tiêu:** Đảm bảo các yêu cầu HTTP/HTTPS với tên máy chủ (hostname) không xác định bị từ chối. Hệ thống phân tích cấu hình NGINX để kiểm tra xem có tồn tại một khối `server` mặc định (catch-all) sử dụng chỉ thị `listen ... default_server;` kết hợp với lệnh `return 444;` (hoặc mã lỗi 4xx) hay không. Đối với HTTPS, kiểm tra thêm chỉ thị `ssl_reject_handshake on;`. Điều này nhằm ngăn chặn máy chủ phản hồi cho các domain tùy ý trỏ đến IP của máy chủ, phòng tránh tấn công Host Header.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector242` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa nội dung liên quan đến việc từ chối các host không xác định (`"Ensure requests for unknown host names are rejected"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ có chứa khối server mặc định (catch-all) đúng chuẩn. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Catch-all HTTP tiêu chuẩn (5 test cases):** Có khối `server` chứa `listen 80 default_server;` (hoặc `listen default_server;`) và `return 444;` để đóng kết nối ngay lập tức.
- **Catch-all trả về mã lỗi 4xx khác (5 test cases):** Có khối `server` mặc định sử dụng `return 400;`, `return 403;`, hoặc `return 404;` thay vì `444`.
- **Catch-all HTTPS tiêu chuẩn (5 test cases):** Có khối `server` chứa `listen 443 default_server ssl;`, `return 444;`, và quan trọng nhất là `ssl_reject_handshake on;` để ngăn chặn rò rỉ chứng chỉ TLS.
- **Catch-all HTTP và HTTPS kết hợp (4 test cases):** Khối `server` lắng nghe đồng thời cả `80 default_server` và `443 default_server ssl`, cấu hình đầy đủ `return 444;` và `ssl_reject_handshake on;`.
- **Sử dụng khối server đầu tiên làm catch-all ngầm định (5 test cases):** Mặc dù NGINX lấy khối server đầu tiên làm mặc định nếu không có `default_server`, test case kiểm tra xem detector có nhận diện khối server đầu tiên chứa `return 444;` là hợp lệ hay không (phụ thuộc vào logic parse toàn cục của `crossplane`).

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình thiếu an toàn, cho phép NGINX xử lý các request có Host header không hợp lệ bằng ứng dụng chính.
- **Thiếu hoàn toàn khối Catch-all (5 test cases):** Không có khối `server` nào chứa chỉ thị `default_server` và cũng không có khối `server` nào chỉ chứa `return 444` (hoặc 4xx). NGINX sẽ dùng khối server đầu tiên (thường là ứng dụng thật) để phản hồi.
- **Có khối default_server nhưng phục vụ nội dung (5 test cases):** Khối `server` có `listen ... default_server;` nhưng lại chứa cấu hình `root`, `index`, hoặc `proxy_pass` thay vì `return 444;`.
- **Thiếu ssl_reject_handshake cho HTTPS (4 test cases):** Khối catch-all có `listen 443 default_server ssl;` và `return 444;` nhưng thiếu `ssl_reject_handshake on;`, dẫn đến nguy cơ rò rỉ chứng chỉ mặc định trước khi kết nối bị đóng.
- **Bỏ lọt Catch-all trên các cổng tùy chỉnh (2 test cases):** Ứng dụng chạy trên các cổng không tiêu chuẩn (ví dụ 8080) nhưng khối catch-all chỉ cấu hình bảo vệ cho cổng 80 và 443, để lọt các request với host name không xác định vào cổng 8080.
- **Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình (`nginx.conf` hoặc file chứa cấu hình `http`).
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục là `"add"`.
  - **`directive`:** Mục tiêu là thêm một khối `"server"` mới hoặc thêm `"ssl_reject_handshake"` vào khối hiện tại.
  - **`context`:** Phải xác định đúng block `http` để chèn khối server catch-all vào đầu tiên, hoặc chỉ định đúng khối `server` đang thiếu an toàn.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST từ `crossplane`, do tính chất của lỗi này yêu cầu phải kiểm tra trên bình diện toàn bộ ngữ cảnh `http` thay vì từng `server` riêng lẻ.
- **Cấu hình an toàn đầy đủ (3 test cases):**
  - Tồn tại một file `default.conf` chứa cấu hình catch-all chuẩn chỉnh, và các file `conf.d/*.conf` khác chứa ứng dụng với `server_name` rõ ràng.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Không tìm thấy default_server trong toàn bộ cấu hình (3 test cases):** Quét qua toàn bộ AST được gộp từ nhiều file và phát hiện vắng mặt hoàn toàn cơ chế catch-all. Báo cáo lỗi ở cấp độ ngữ cảnh `http`.
- **Gom nhóm lỗi (Grouping) (3 test cases):** Đảm bảo hệ thống chỉ báo cáo 1 lỗi duy nhất về việc thiếu catch-all block cho mỗi block `http` (thường chỉ có 1 block `http` trong NGINX), tránh spam lỗi nếu có nhiều file cấu hình.
- **Xử lý các ngoại lệ (3 test cases):** Phân tích đúng các trường hợp `listen` viết tắt, port tùy chỉnh, hoặc các từ khóa xen kẽ trong chỉ thị `listen` (như `listen 8080 default_server proxy_protocol;`).
- **Tương tác với Include Directive phức tạp (5 test cases):** Xử lý các kịch bản file `nginx.conf` chứa nhiều lệnh `include` lồng nhau. Đảm bảo scanner quét đúng thứ tự và không bỏ sót hay tính lặp khối `default_server` nằm ẩn sâu trong cấu trúc thư mục, đồng thời đưa ra đường dẫn `file` khắc phục chính xác.
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận đối tượng kết quả `scan()` chứa đủ thông tin để Auto-Remediation có thể tự động tạo ra một file mới (ví dụ: `00-catchall.conf`) chứa khối server catch-all chuẩn hoặc chèn trực tiếp vào `nginx.conf` mà không phá vỡ cấu trúc.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector242` được thiết kế chặt chẽ nhằm bảo vệ máy chủ khỏi các lưu lượng rác và tấn công Host Header:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Việc chặn các request tới IP trực tiếp hoặc hostname chưa đăng ký là một bước làm cứng (hardening) cơ bản nhưng rất quan trọng của NGINX. Việc tự động phát hiện lỗi này đôi khi phức tạp vì cần phân tích toàn cục thay vì cục bộ. Các test cases này đảm bảo công cụ DevSecOps có thể xác minh sự tồn tại và tính hợp lệ của khối catch-all (đặc biệt là tính năng `ssl_reject_handshake` trên NGINX >= 1.19.4). Đồng thời, dữ liệu trả về hỗ trợ Thành viên 2 (Auto-Remediation) có thể dễ dàng sinh code diff an toàn, giúp tạo ra một server block "đỡ đạn" cho toàn bộ hệ thống web.
