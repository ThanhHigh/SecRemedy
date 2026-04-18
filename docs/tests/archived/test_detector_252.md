# Tài liệu Kiểm thử: CIS Benchmark 2.5.2 (Detector 252)

**Mục tiêu:** Đảm bảo các trang lỗi mặc định (ví dụ: 404, 50x) và trang `index.html` mặc định không chứa thông tin hoặc tham chiếu đến NGINX (chuẩn CIS Benchmark 2.5.2). Việc NGINX hiển thị trang lỗi mặc định sẽ làm lộ thông tin về web server đang sử dụng, tạo điều kiện cho kẻ tấn công (reconnaissance) tìm kiếm các lỗ hổng đã biết. Hệ thống sử dụng thư viện `crossplane` để phân tích đệ quy cấu hình NGINX, kiểm tra ngữ cảnh `http` và `server` để đảm bảo chỉ thị `error_page` được cấu hình để chuyển hướng lỗi sang các trang tĩnh tùy chỉnh.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector252` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure default error and index.html pages do not reference NGINX"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các khối cấu hình tuân thủ việc thiết lập `error_page` trỏ tới trang lỗi tùy chỉnh (custom error pages). Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Thiết lập an toàn tại khối `http` (6 test cases):** Các cấu hình khai báo rõ ràng các chỉ thị `error_page 404 /404.html;` và `error_page 500 502 503 504 /50x.html;` ngay trong khối `http` của `nginx.conf`, đảm bảo tính kế thừa cho toàn bộ server.
- **Thiết lập an toàn tại khối `server` (6 test cases):** Các trường hợp cấu hình chi tiết định nghĩa `error_page` ở từng block `server` cụ thể để phục vụ trang lỗi riêng cho từng domain (ví dụ: `server { error_page 404 /custom_404.html; ... }`).
- **Kiểm tra lồng ghép đệ quy và cấu hình location tương ứng (Nested Contexts) (6 test cases):** Trình phân tích xác nhận rằng khi có `error_page`, cấu hình cũng có thể bao gồm khối `location` tương ứng (ví dụ: `location = /50x.html { ... }`) hợp lệ và không trỏ về trang mặc định của NGINX.
- **Kết hợp với các chỉ thị bảo mật khác (6 test cases):** Chỉ thị nằm xen kẽ giữa các cấu hình phức tạp (ví dụ: đứng cùng `server_tokens off;`, `add_header`, v.v.) mà không làm ảnh hưởng đến logic phân tích.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình thiếu sót hoặc để lộ thông tin qua trang lỗi mặc định, kích hoạt cảnh báo vi phạm để chuyển dữ liệu JSON Contract cho module Auto-Remediation (Thành viên 2).
- **Không khai báo `error_page` (Implicitly default) (6 test cases):** Khối `http` và `server` hoàn toàn vắng mặt chỉ thị `error_page`. NGINX sẽ render HTML mặc định có chứa chữ "nginx". Đây là vi phạm phổ biến nhất.
- **Khai báo `error_page` nhưng thiếu mã lỗi quan trọng (5 test cases):** Quản trị viên cấu hình `error_page` cho lỗi 404 nhưng quên cấu hình cho dải lỗi server 50x (500, 502, 503, 504), khiến hệ thống vẫn có nguy cơ rò rỉ thông tin khi gặp sự cố backend.
- **Cấu hình `error_page` nhưng trỏ sai vị trí hoặc nghi ngờ dùng trang mặc định (4 test cases):** Kiểm tra các dạng cấu hình rỗng hoặc có cú pháp khai báo lỗi nhưng không hợp lý theo chuẩn bảo mật.
- **Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình NGINX chứa khối `http` hoặc `server` cần bổ sung.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Do thiếu cấu hình, action chủ yếu là `"add"` hoặc `"insert"` (thêm dòng mới `error_page`).
  - **`directive`:** Mục tiêu là chỉ thị `"error_page"`.
  - **`value`:** Giá trị mong muốn (ví dụ: `"404 /404.html"` hoặc `"500 502 503 504 /50x.html"`).
  - **`context`:** Phải chứa đối tượng định vị chính xác vị trí AST (ví dụ: node của khối `server`) để công cụ diff/Dry-Run có thể hoạt động chính xác.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy từ `crossplane` trên toàn bộ thư mục NGINX.
- **Cấu hình an toàn trên toàn bộ hệ thống (3 test cases):** Hệ thống bao gồm nhiều file `conf.d/*.conf`, có `error_page` cấu hình đầy đủ tại gốc `nginx.conf` hoặc ở tất cả các `server` block. *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases):** Phân tích toàn bộ cây thư mục và phát hiện một số virtual host (`server` block) trong `conf.d/` không kế thừa hoặc không tự định nghĩa `error_page`.
- **Gom nhóm lỗi (Grouping) và cảnh báo ghi đè (3 test cases):** Nếu `nginx.conf` đã đặt `error_page`, nhưng một file `api.conf` lại vô tình thiết lập lại logic lỗi không an toàn hoặc ghi đè, Scanner phải khoanh vùng chính xác file bị lỗi.
- **Xử lý các ngoại lệ cấu hình (3 test cases):** Xử lý an toàn khi file cấu hình hoàn toàn trống, hoặc chỉ chứa block không liên quan (như `stream`), đảm bảo logic quét không bị gián đoạn.
- **Tương tác với Include Directive phức tạp (5 test cases):** Khả năng đệ quy `crossplane` (ví dụ: `nginx.conf` -> `include conf.d/*` -> định nghĩa `server`). Nếu `server` block trong file con thiếu `error_page`, báo cáo phải trỏ đúng file con đó.
- **Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases):** Đảm bảo JSON Contract do Thành viên 1 tạo ra cung cấp tọa độ dòng chính xác để Thành viên 2 chèn các dòng `error_page ...;` vào cấu hình. Việc này đòi hỏi AST định vị đúng khối `server` để sửa chữa, cho phép lệnh `nginx -t` kiểm tra cấu trúc ngoặc sau khi Dry-Run.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector252` được thiết kế chặt chẽ nhằm bảo vệ máy chủ khỏi nguy cơ rò rỉ công nghệ nền tảng, bám sát các tiêu chí của đồ án tốt nghiệp:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích (Context Đồ án):** Tương tự CIS 2.5.1, CIS 2.5.2 tập trung vào việc xử lý trường hợp **"thiếu sót"** (missing directive). NGINX mặc định không bắt buộc phải có `error_page`, nên Scanner (Thành viên 1) phải tìm kiếm sự vắng mặt của nó trong toàn bộ các khối `http` và `server`. JSON Contract sinh ra phải hướng dẫn rõ ràng cho module Auto-Remediation (Thành viên 2) chèn thêm chỉ thị `"add"` một cách an toàn mà không phá vỡ cú pháp. Điều này giúp hệ thống tự động hoàn thiện cấu hình mà vẫn đảm bảo tính ổn định (Zero-Downtime) sau khi chạy `nginx -t`.