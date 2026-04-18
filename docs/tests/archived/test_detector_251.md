# Tài liệu Kiểm thử: CIS Benchmark 2.5.1 (Detector 251)

**Mục tiêu:** Đảm bảo chỉ thị `server_tokens` trong NGINX được thiết lập thành `off`. Theo chuẩn CIS Benchmark 2.5.1, việc vô hiệu hóa chỉ thị này sẽ ẩn thông tin về phiên bản NGINX và hệ điều hành trên các trang lỗi cũng như trong HTTP header `Server`. Hệ thống sử dụng thư viện `crossplane` để phân tích đệ quy cấu hình NGINX, kiểm tra ngữ cảnh `http`, `server` và `location` để đối chiếu giá trị của `server_tokens`. Việc này nhằm thu hẹp bề mặt tấn công (attack surface), ngăn chặn kẻ gian thu thập thông tin (reconnaissance) để tìm kiếm các lỗ hổng đã biết trên phiên bản NGINX cụ thể.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector251` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure server_tokens directive is set to off"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các khối cấu hình tuân thủ nghiêm ngặt việc đặt `server_tokens off;`. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Thiết lập an toàn tại khối `http` (6 test cases):** Các cấu hình khai báo rõ ràng `server_tokens off;` ngay trong khối `http` của `nginx.conf`, đảm bảo tính kế thừa an toàn cho toàn bộ hệ thống. Bao gồm cả các trường hợp có comment bên cạnh dòng lệnh.
- **Thiết lập an toàn tại khối `server` và `location` (6 test cases):** Các trường hợp cấu hình chi tiết ghi đè giá trị an toàn ở từng block `server` hoặc `location` cụ thể (ví dụ: `server { server_tokens off; ... }`).
- **Kiểm tra lồng ghép đệ quy (Nested Contexts) (6 test cases):** Trình phân tích phải đệ quy qua tất cả các khối `server` và `location` (kể cả location lồng nhau) để đảm bảo không có block con nào vô tình hoặc cố ý ghi đè `server_tokens on;` trái phép, bất chấp việc khối `http` gốc có an toàn hay không.
- **Kết hợp với các chỉ thị bảo mật/hiệu suất khác (6 test cases):** Chỉ thị nằm xen kẽ giữa các cấu hình phức tạp (ví dụ: đứng trước `sendfile on;`, xen giữa các chỉ thị `add_header`, v.v.).

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình để lộ thông tin phiên bản (hoặc do khai báo sai, hoặc do thiếu sót), kích hoạt cảnh báo vi phạm để chuyển dữ liệu JSON Contract cho module Auto-Remediation (Thành viên 2).
- **Không khai báo `server_tokens` (Implicitly 'on') (6 test cases):** Vì giá trị mặc định của NGINX là `on`, việc khối `http` thiếu vắng hoàn toàn chỉ thị `server_tokens` bị coi là vi phạm nghiêm trọng.
- **Khai báo rõ ràng `server_tokens on;` (5 test cases):** Người quản trị cố tình hoặc vô tình bật tính năng này tại khối `http`, `server` hoặc `location`.
- **Sử dụng các giá trị ngoại lệ khác `off` (4 test cases):** NGINX Plus hỗ trợ các giá trị như `build` hoặc một chuỗi tùy chỉnh (custom string). Theo chuẩn CIS 2.5.1 cho NGINX mã nguồn mở, bất kỳ giá trị nào khác `off` đều bị coi là vi phạm.
- **Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình NGINX chứa khối `http` cần sửa.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Nếu chỉ thị đã tồn tại nhưng sai giá trị, action là `"modify"` (sửa `on` thành `off`). Nếu chỉ thị bị thiếu hoàn toàn, action phải là `"add"` hoặc `"insert"` (thêm dòng mới).
  - **`directive`:** Mục tiêu là chỉ thị `"server_tokens"`.
  - **`value`:** Giá trị mong muốn là `"off"`.
  - **`context`:** Phải chứa đối tượng định vị chính xác vị trí AST (ví dụ: node của khối `http`) để công cụ diff/Dry-Run có thể hoạt động chính xác.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy từ `crossplane` trên toàn bộ thư mục NGINX.
- **Cấu hình an toàn trên toàn bộ hệ thống (3 test cases):** Hệ thống bao gồm nhiều file `conf.d/*.conf`, có `server_tokens off;` cấu hình tại gốc `nginx.conf`. *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases):** Phân tích toàn bộ cây thư mục và xác định đúng rằng không có file nào chứa chỉ thị này, từ đó chỉ định `nginx.conf` (nơi chứa khối `http`) là điểm cần chèn thêm cấu hình.
- **Gom nhóm lỗi (Grouping) và cảnh báo ghi đè (3 test cases):** Nếu `nginx.conf` đã đặt `off`, nhưng một file `api.conf` lại đặt `server_tokens on;` ở khối `server`, Scanner phải khoanh vùng chính xác lỗi nằm ở `api.conf` chứ không phải file gốc.
- **Xử lý các ngoại lệ cấu hình (3 test cases):** Xử lý an toàn khi file cấu hình hoàn toàn trống, hoặc thiếu vắng khối `http` (chỉ có event hoặc stream blocks), đảm bảo logic phân tích không bị crash.
- **Tương tác với Include Directive phức tạp (5 test cases):** Kiểm tra khả năng đệ quy `crossplane` qua nhiều cấp (ví dụ: `nginx.conf` -> `include conf.d/*` -> `include common/security.conf`). Nếu lỗi nằm ở file `security.conf`, báo cáo phải chỉ đích danh file đó.
- **Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases):** Đảm bảo JSON Contract trả về từ Thành viên 1 chứa đầy đủ Payload (tọa độ dòng, node AST, loại action "add/modify") để Thành viên 2 dễ dàng render ra Code Diff (hiển thị `+ server_tokens off;` màu xanh) và tiến hành Dry-Run an toàn qua câu lệnh `nginx -t`.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector251` được thiết kế chặt chẽ nhằm bảo vệ máy chủ khỏi nguy cơ rò rỉ phiên bản và đáp ứng đúng tiêu chí đánh giá của đồ án tốt nghiệp:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích (Context Đồ án):** Đặc thù của CIS 2.5.1 phức tạp hơn CIS 2.4.1 ở chỗ hệ thống không chỉ tìm dòng sai để xóa/sửa, mà còn phải xử lý trường hợp **"thiếu sót"** (missing directive) do mặc định NGINX coi là `on`. Scanner của Thành viên 1 phải phân tích AST để xác định vị trí an toàn nhất (khối `http`) để chèn mã. Sự chính xác của JSON Contract (hành động `"add"`) quyết định việc Thành viên 2 có thể tự động chèn dòng một cách an toàn mà không phá vỡ cấu trúc ngoặc nhọn `{}` của NGINX, đóng góp trực tiếp vào mục tiêu Zero-Downtime và Safe Remediation.

