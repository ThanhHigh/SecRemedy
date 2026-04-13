# Tài liệu Kiểm thử: CIS Benchmark 4.1.1 (Detector 411)

**Mục tiêu:** Đảm bảo tất cả lưu lượng HTTP (không mã hóa) được chuyển hướng sang HTTPS (mã hóa). Hệ thống phân tích cấu hình NGINX để kiểm tra xem các server block lắng nghe trên cổng 80 (HTTP) có cấu hình chuyển hướng an toàn (thường thông qua chỉ thị `return 301 https://$host$request_uri;`) hay không, nhằm đảm bảo mọi giao tiếp giữa người dùng và máy chủ đều được bảo mật.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector411` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"4.1.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa nội dung liên quan đến việc chuyển hướng HTTP sang HTTPS (`"Ensure HTTP is redirected to HTTPS"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ có chứa các chỉ thị chuyển hướng hoặc chỉ phục vụ HTTPS. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Chuyển hướng tiêu chuẩn bằng return (5 test cases):** Khối `server` lắng nghe cổng 80 có chứa `return 301 https://$host$request_uri;` để chuyển hướng vĩnh viễn toàn bộ truy cập.
- **Chuyển hướng bằng các mã trạng thái khác hoặc biến khác (5 test cases):** Sử dụng `return 302` (chuyển hướng tạm thời) sang HTTPS, hoặc dùng `https://$server_name$request_uri;`.
- **Chuyển hướng bằng rewrite (4 test cases):** Khối `server` cổng 80 sử dụng chỉ thị `rewrite` thay vì `return`, ví dụ `rewrite ^ https://$host$request_uri? permanent;`.
- **Server chỉ phục vụ HTTPS (5 test cases):** Khối `server` chỉ có chỉ thị `listen 443 ssl;` và không mở cổng 80. Các cấu hình này mặc định tuân thủ vì không tiếp nhận HTTP.
- **Chuyển hướng có điều kiện (5 test cases):** Khối `server` lắng nghe cả cổng 80 và 443, nhưng có khối `if` kiểm tra scheme: `if ($scheme != "https") { return 301 https://$host$request_uri; }`. Mặc dù `if` trong NGINX đôi khi không được khuyến khích, nhưng về mặt logic chuyển hướng thì vẫn hợp lệ.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 20 Test Cases
Kiểm tra các cấu hình mở cổng HTTP nhưng không ép buộc chuyển hướng sang HTTPS, tiềm ẩn nguy cơ truyền tải dữ liệu không mã hóa.
- **Thiếu chỉ thị chuyển hướng (5 test cases):** Khối `server` có `listen 80;` phục vụ nội dung trực tiếp (như cấu hình `root`, `index`) mà không có bất kỳ lệnh `return` hoặc `rewrite` nào sang HTTPS.
- **Chuyển hướng sai đích (5 test cases):** Khối `server` cổng 80 có lệnh `return` nhưng lại chuyển hướng đến một địa chỉ `http://` khác thay vì `https://`.
- **Lắng nghe đồng thời không ép buộc (4 test cases):** Khối `server` có cả `listen 80;` và `listen 443 ssl;` nhưng phục vụ nội dung chung, không có cơ chế tách biệt hay ép buộc HTTP phải chuyển sang HTTPS.
- **Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình chứa khối server vi phạm.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục là `"add"` hoặc `"modify"` (để thêm lệnh `return 301 https://$host$request_uri;`).
  - **`directive`:** Mục tiêu là `"return"`.
  - **`context`:** Phải xác định đúng block `server` đang lắng nghe cổng 80 để tiến hành khắc phục.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 15 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST từ `crossplane`, đảm bảo hệ thống quét và nhận diện trên toàn bộ ngữ cảnh cấu hình NGINX.
- **Cấu hình an toàn đầy đủ (3 test cases):**
  - Mọi cấu hình HTTP (`listen 80`) trong `nginx.conf` và các file `conf.d/*.conf` đều đóng vai trò là khối chuyển hướng sang HTTPS, và các khối phục vụ thực tế đều dùng `listen 443 ssl`.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhiều file cấu hình vi phạm (3 test cases):** Quét thấy một số ứng dụng (như `admin.conf`) đã cấu hình chuyển hướng tốt, nhưng một số khác (như `legacy.conf`) lại mở cổng 80 không bảo mật. Báo cáo cần chỉ đích danh file và khối bị lỗi.
- **Gom nhóm lỗi (Grouping) (3 test cases):** Nếu trong cùng một file có nhiều server block vi phạm (ví dụ nhiều domain đều không cấu hình HTTPS redirect), hệ thống gom các lỗi này theo file một cách logic.
- **Xử lý các ngoại lệ (3 test cases):** Bỏ qua các khối `server` không có `listen 80` (chỉ dùng cho tác vụ nội bộ hoặc cổng khác không liên quan đến HTTP/HTTPS web traffic).
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận đối tượng kết quả `scan()` chứa đủ thông tin để Auto-Remediation có thể tự động tạo ra một khối `server` cấu hình chuyển hướng chuẩn (hoặc chèn lệnh `return` vào khối hiện tại) mà không làm gián đoạn dịch vụ.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector411` được thiết kế chặt chẽ nhằm đảm bảo mọi luồng truy cập web đều được mã hóa:
- **Tổng số lượng test cases:** **63 test cases** (4 + 24 + 20 + 15)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Việc mã hóa lưu lượng truy cập bằng HTTPS là tiêu chuẩn bắt buộc cho các ứng dụng web hiện đại nhằm chống lại các cuộc tấn công nghe lén (Man-in-the-Middle). Dù CIS Benchmark 4.1.1 đánh giá ở mức thủ công (Manual), nhưng việc tự động nhận diện các cổng 80 chưa được chuyển hướng giúp rút ngắn thời gian rà soát. Các test cases bao phủ toàn diện từ các cú pháp NGINX truyền thống đến các cách viết `rewrite` hay `if`, đảm bảo công cụ DevSecOps đánh giá chính xác độ an toàn và cung cấp đúng dữ liệu cho module Auto-Remediation (Member 2) sinh ra bản vá (Code Diff) thêm khối chuyển hướng một cách an toàn nhất.