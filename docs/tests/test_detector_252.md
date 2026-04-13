# Tài liệu Kiểm thử: CIS Benchmark 2.5.2 (Detector 252)

**Mục tiêu:** Đảm bảo các trang báo lỗi mặc định (ví dụ: 404, 50x) và trang `index.html` mặc định không tham chiếu đến NGINX. Thông qua việc phân tích cấu hình, hệ thống đảm bảo cấu hình NGINX có định nghĩa rõ ràng các chỉ thị `error_page` để sử dụng các trang lỗi tùy chỉnh thay cho các trang mặc định của NGINX (nhằm tránh tiết lộ thông tin máy chủ).

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector252` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.2"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa nội dung liên quan đến việc ẩn thông tin trên `"error and index.html pages"`.
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ có chứa chỉ thị `error_page` để tùy chỉnh các trang báo lỗi. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Lỗi phổ biến 4xx (5 test cases):** Khối `http` hoặc `server` có `error_page 404 /404.html;`, `error_page 403 /403.html;`, `error_page 400 401 403 404 /4xx.html;`.
- **Lỗi hệ thống 5xx (5 test cases):** Khối `http` hoặc `server` có khai báo trang lỗi máy chủ như `error_page 500 502 503 504 /50x.html;`, `error_page 500 /500.html;`.
- **Khai báo error_page kèm thay đổi mã phản hồi (4 test cases):** Cấu hình định tuyến lại mã phản hồi như `error_page 404 =200 /empty.gif;` hoặc `error_page 404 = /404.php;` vẫn được coi là hợp lệ.
- **Cấu hình kết hợp nhiều cấp độ (5 test cases):** Cả khối `http`, `server` và `location` đều có cấu hình `error_page` hợp lệ ghi đè hoặc bổ sung cho nhau mà không bị lỗi.
- **Vị trí file tùy chỉnh khác nhau (5 test cases):** Trang báo lỗi được trỏ tới các đường dẫn tùy chỉnh hợp lệ trong hệ thống như `error_page 404 /custom_errors/404.html;` hoặc nằm ở các file include trong thư mục `conf.d/`.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 20 Test Cases
Kiểm tra các cấu hình không định nghĩa `error_page` (đặc biệt đối với các mã lỗi nghiêm trọng) dẫn đến nguy cơ sử dụng trang lỗi mặc định của NGINX.
- **Thiếu error_page hoàn toàn (5 test cases):** Các khối `http` và `server` không có bất kỳ chỉ thị `error_page` nào được định nghĩa.
- **Chỉ khai báo một phần lỗi (5 test cases):** Có khai báo `error_page 404;` nhưng thiếu khai báo bao phủ các lỗi 5xx (ví dụ 500, 502, 503, 504) khiến trang 5xx mặc định vẫn hiển thị thông tin NGINX.
- **Lỗi cú pháp hoặc thiếu URL đích (4 test cases):** Cấu hình `error_page` không đầy đủ như `error_page 404;` (thiếu đường dẫn file html) không có tác dụng bảo vệ.
- **Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình bị vi phạm.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"add"` (để thêm chỉ thị `error_page` vào cấu hình nếu chưa có).
  - **`directive`:** Mục tiêu là `"error_page"`.
  - **`context`:** Phải xác định đúng block (thường là `server` hoặc `http`) cần chèn cấu hình khắc phục.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 15 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST từ `crossplane`, đảm bảo hệ thống quét và nhận diện trên toàn bộ ngữ cảnh cấu hình NGINX.
- **Cấu hình an toàn đầy đủ (3 test cases):**
  - Toàn bộ các file `nginx.conf` và các file vhost trong `conf.d/` đều kế thừa hoặc tự định nghĩa đầy đủ `error_page` cho 4xx và 5xx.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhiều file cấu hình vi phạm (3 test cases):** Quét thấy một số khối `server` trong `api.conf` hoặc `admin.conf` không định nghĩa `error_page` cũng như không kế thừa từ `http` block. Hệ thống báo cáo chi tiết vi phạm tại từng file.
- **Gom nhóm lỗi (Grouping) (3 test cases):** Nếu trong cùng một file cấu hình có nhiều khối `server` cùng vi phạm lỗi thiếu `error_page`, hệ thống sẽ gom nhóm các lỗi này theo file một cách rành mạch.
- **Xử lý khối server rỗng hoặc redirect (3 test cases):** Bỏ qua các khối `server` chỉ dùng để redirect (như return 301) mà không thực sự phục vụ nội dung web, tránh báo lỗi giả.
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận đối tượng kết quả `scan()` chứa đủ thông tin để Auto-Remediation có thể tự động bơm các dòng như `error_page 500 502 503 504 /50x.html;` và `error_page 404 /404.html;` vào đúng vị trí an toàn.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector252` được thiết kế chặt chẽ nhằm đảm bảo việc giám sát cấu hình xử lý trang báo lỗi đạt hiệu quả tối đa:
- **Tổng số lượng test cases:** **63 test cases** (4 + 24 + 20 + 15)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Mặc dù CIS Benchmark phân loại 2.5.2 là kiểm tra (Manual) do cần đảm bảo nội dung file html không chứa chữ NGINX, bộ kiểm thử này tập trung vào việc xác minh sự tồn tại của cấu trúc `error_page` trong AST cấu hình NGINX. Việc bắt buộc định nghĩa `error_page` cho các mã lỗi phổ biến (đặc biệt là 5xx) giúp triệt tiêu rủi ro lộ lọt thông tin phần mềm máy chủ, đồng thời tích hợp chặt chẽ với cơ chế Auto-Remediation để chuẩn hóa hạ tầng bảo mật theo đúng khuyến nghị của luận văn.
