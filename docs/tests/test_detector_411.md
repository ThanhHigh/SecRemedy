# Tài liệu Kiểm thử: CIS Benchmark 4.1.1 (Detector 411)

**Mục tiêu:** Đảm bảo mọi lưu lượng truy cập HTTP (không mã hóa, thường ở port 80) đều được tự động chuyển hướng (redirect) sang HTTPS (mã hóa, port 443) nhằm bảo vệ an toàn dữ liệu người dùng (chuẩn CIS Benchmark 4.1.1). Việc NGINX cho phép kết nối HTTP trực tiếp mà không chuyển hướng sẽ làm giảm mức độ tin cậy của website và tạo điều kiện cho các cuộc tấn công nghe lén (Man-in-the-Middle). Hệ thống sử dụng thư viện `crossplane` để phân tích đệ quy cấu hình NGINX, kiểm tra các khối `server` có chỉ thị `listen 80` (hoặc tương đương) để đảm bảo tồn tại chỉ thị `return 301 https://$host$request_uri;` (hoặc tương tự) thực hiện việc chuyển hướng.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector411` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"4.1.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure HTTP is redirected to HTTPS"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các khối cấu hình tuân thủ việc thiết lập chuyển hướng HTTP sang HTTPS một cách an toàn. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Thiết lập chuyển hướng chuẩn 301 (6 test cases):** Khối `server` lắng nghe port 80 (`listen 80;`) và chứa chỉ thị chuyển hướng vĩnh viễn `return 301 https://$host$request_uri;` chuẩn xác.
- **Thiết lập chuyển hướng dùng biến máy chủ khác (6 test cases):** Các cấu hình sử dụng `return 301 https://$server_name$request_uri;` hoặc các biến hợp lệ khác của NGINX để redirect, hệ thống nhận diện đây là hành vi an toàn.
- **Cấu hình khối server riêng biệt cho HTTP và HTTPS (6 test cases):** Trình phân tích xác nhận kiến trúc phân tách rõ ràng: một khối `server` chỉ dành cho port 80 có nhiệm vụ duy nhất là chuyển hướng (`return 301...`), và khối `server` khác lắng nghe port 443 (`listen 443 ssl;`) để xử lý logic thực tế.
- **Kết hợp với các chỉ thị cấu hình khác (6 test cases):** Chỉ thị chuyển hướng nằm xen kẽ với `server_name`, `access_log`, `error_log` trong khối HTTP mà không làm ảnh hưởng đến quá trình phân tích logic chuyển hướng.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình thiếu sót khiến lưu lượng HTTP không bị chuyển hướng, kích hoạt cảnh báo vi phạm để chuyển dữ liệu JSON Contract cho module Auto-Remediation (Thành viên 2).
- **Không có chỉ thị `return` hoặc `rewrite` (Implicitly insecure) (6 test cases):** Khối `server` lắng nghe port 80 nhưng xử lý trực tiếp request (có `root`, `index`, `location / { ... }`) mà hoàn toàn vắng mặt cấu hình chuyển hướng. Đây là lỗi phổ biến nhất.
- **Khai báo `return` nhưng không chuyển hướng sang HTTPS (5 test cases):** Quản trị viên sử dụng `return 200 "OK";` hoặc chuyển hướng sang một HTTP URL khác (`return 301 http://www.example.com;`), không đạt yêu cầu mã hóa.
- **Cấu hình chuyển hướng nhưng đặt sai vị trí hoặc cú pháp (4 test cases):** Chỉ thị `return` đặt trong một `location` cụ thể thay vì toàn khối `server` (có thể gây lọt request ở các path khác), hoặc cú pháp redirect không trọn vẹn.
- **Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình NGINX chứa khối `server` HTTP vi phạm.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Thường là `"replace_block"` hoặc `"add"` để thay thế nội dung khối server 80 hiện tại bằng lệnh redirect, hoặc chèn mới.
  - **`directive`:** Mục tiêu là chỉ thị `"return"`.
  - **`value`:** Giá trị mong muốn (ví dụ: `"301 https://$host$request_uri"`).
  - **`context`:** Phải chứa đối tượng định vị chính xác vị trí AST của khối `server` HTTP để module Auto-Remediation có thể chỉnh sửa/thay thế mã nguồn cấu hình chính xác và tạo Code Diff cho Dry-Run.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy từ `crossplane` trên toàn bộ thư mục NGINX.
- **Cấu hình an toàn đồng bộ trên toàn bộ hệ thống (3 test cases):** Hệ thống có nhiều file `conf.d/*.conf` (như `admin.emarket.me.conf`, `vendor.emarket.me.conf`), tất cả các khối server HTTP đều thực hiện redirect chuẩn chỉ. *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhận diện sót lọt cấu hình ở hệ thống đa tệp (3 test cases):** Phân tích toàn bộ cây thư mục và phát hiện một số virtual host quên không cấu hình redirect HTTPS trong khi các host khác thì có.
- **Phân loại chính xác khối Server (HTTP vs HTTPS) (3 test cases):** Đảm bảo Scanner chỉ kiểm tra và báo cáo vi phạm trên các khối `server` lắng nghe port 80, không báo lỗi nhầm trên các khối `server` lắng nghe 443 (đã mã hóa).
- **Xử lý các cấu hình port phức tạp (3 test cases):** Kiểm tra khi server lắng nghe trên nhiều port hoặc các port non-standard (vd: `listen 8080;`), xác định đúng mục tiêu cần mã hóa.
- **Tương tác với Include Directive (5 test cases):** Đánh giá cấu trúc đệ quy (ví dụ: `nginx.conf` include `conf.d/*.conf`). Nếu một file con định nghĩa server HTTP không có redirect, JSON Contract phải trỏ chính xác về file con đó.
- **Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases):** Đảm bảo JSON Contract do Thành viên 1 tạo ra cung cấp tọa độ block/dòng cực kỳ chính xác. Vì việc biến đổi một khối server HTTP xử lý nội dung thành một khối redirect thường đòi hỏi xóa các chỉ thị cũ (như `location`, `root`) và chèn `return 301 ...;`, tọa độ AST chuẩn là bắt buộc để Thành viên 2 thực hiện thao tác an toàn và vượt qua được bài test `nginx -t`.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector411` được thiết kế chặt chẽ nhằm bảo đảm việc thực thi mã hóa đường truyền cho mọi request, bám sát các yêu cầu khắt khe của đồ án DevSecOps:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích (Context Đồ án):** Không giống như các chỉ thị đơn lẻ (chỉ cần thêm 1 dòng), việc khắc phục lỗi 4.1.1 có tính cấu trúc cao. Scanner (Thành viên 1) phải xác định được toàn bộ khối `server` HTTP đang vi phạm để JSON Contract báo cáo. Module Auto-Remediation (Thành viên 2) sẽ phải cực kỳ cẩn thận khi cấu trúc lại khối này thành dạng redirect 301 thuần túy. Code Diff sinh ra (Dry-Run) phải cực kỳ rõ ràng để người dùng phê duyệt qua UI. Quá trình kiểm tra cú pháp `nginx -t` tự động sau đó đóng vai trò chốt chặn an toàn (Zero-Downtime) nhằm tránh rủi ro sập hệ thống do sửa sai ngoặc `{ }` hoặc mất cấu hình quan trọng.