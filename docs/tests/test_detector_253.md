# Tài liệu Kiểm thử: CIS Benchmark 2.5.3 (Detector 253)

**Mục tiêu:** Đảm bảo tính năng phục vụ các file ẩn (hidden files) bị vô hiệu hóa. Hệ thống phân tích cấu hình NGINX để đảm bảo có khối `location` từ chối truy cập vào các file hoặc thư mục bắt đầu bằng dấu chấm (ví dụ: `.git`, `.env`), nhằm tránh rò rỉ mã nguồn, thông tin cấu hình và dữ liệu nhạy cảm.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector253` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.3"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa nội dung liên quan đến việc vô hiệu hóa phục vụ file ẩn (`"Ensure hidden file serving is disabled"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ có chứa chỉ thị `location` để chặn truy cập vào các file ẩn. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Khai báo từ chối tiêu chuẩn (5 test cases):** Khối `server` có chứa `location ~ /\. { deny all; }` để từ chối tất cả yêu cầu.
- **Khai báo từ chối bằng mã trạng thái (5 test cases):** Khối `server` sử dụng `return` thay cho `deny`, ví dụ `location ~ /\. { return 404; }` hoặc `return 403;`.
- **Có ngoại lệ hợp lệ (Let's Encrypt) (5 test cases):** Cấu hình chặn file ẩn nhưng có cho phép các ngoại lệ cần thiết như ACME challenge: `location ~ /\.well-known/acme-challenge { allow all; }`.
- **Vị trí file cấu hình include (4 test cases):** Chỉ thị từ chối file ẩn được bao gồm (include) từ một file snippet dùng chung, ví dụ `include snippets/deny-hidden-files.conf;` và AST parser có thể phân tích được.
- **Khai báo Regular Expression nâng cao (5 test cases):** Các biểu thức chính quy phức tạp nhưng đảm bảo chặn an toàn các file ẩn như `location ~ /\.(?!well-known).* { deny all; }`.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 20 Test Cases
Kiểm tra các cấu hình không định nghĩa việc chặn file ẩn, dẫn đến nguy cơ NGINX phục vụ các file nhạy cảm.
- **Thiếu location chặn hoàn toàn (5 test cases):** Khối `server` không có bất kỳ khối `location` nào chứa regex chặn file ẩn (`/\.`).
- **Chặn không đầy đủ (5 test cases):** Chỉ chặn một số file ẩn cụ thể thay vì tất cả (ví dụ `location ~ /\.ht { deny all; }` hoặc `location ~ /\.git { deny all; }`), bỏ sót `.env` hoặc các file ẩn khác.
- **Hành động không bảo mật (4 test cases):** Có định nghĩa `location ~ /\. { ... }` nhưng bên trong lại là `allow all;` hoặc không có chỉ thị từ chối truy cập.
- **Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình có khối server bị vi phạm.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"add"` (để thêm khối `location` chặn file ẩn vào).
  - **`directive`:** Mục tiêu là `"location"`.
  - **`context`:** Phải xác định đúng block `server` cần chèn cấu hình khắc phục.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 15 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST từ `crossplane`, đảm bảo hệ thống quét và nhận diện trên toàn bộ ngữ cảnh cấu hình NGINX.
- **Cấu hình an toàn đầy đủ (3 test cases):**
  - Toàn bộ các file `nginx.conf` và các file vhost trong `conf.d/` đều có khối `location` chặn file ẩn trong tất cả các `server` blocks phục vụ nội dung web.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhiều file cấu hình vi phạm (3 test cases):** Quét thấy một số khối `server` có chặn nhưng một số khối khác trong file `api.conf` hoặc `default.conf` thì không. Hệ thống báo cáo chi tiết vi phạm tại từng file và từng block.
- **Gom nhóm lỗi (Grouping) (3 test cases):** Nếu trong cùng một file cấu hình có nhiều khối `server` vi phạm lỗi không chặn file ẩn, hệ thống sẽ gom nhóm các lỗi này theo file một cách rành mạch.
- **Xử lý khối server rỗng hoặc redirect (3 test cases):** Bỏ qua các khối `server` chỉ dùng để redirect (như `return 301`) mà không có `root` hoặc không thực sự phục vụ file tĩnh, tránh báo lỗi giả.
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận đối tượng kết quả `scan()` chứa đủ thông tin để Auto-Remediation có thể tự động bơm khối `location ~ /\. { deny all; access_log off; log_not_found off; }` vào đúng khối `server`.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector253` được thiết kế chặt chẽ nhằm triệt tiêu rủi ro lộ lọt cấu hình, metadata qua các file ẩn:
- **Tổng số lượng test cases:** **63 test cases** (4 + 24 + 20 + 15)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Việc chặn các file ẩn (hidden files) là một khía cạnh bảo mật đặc biệt quan trọng để ngăn chặn rò rỉ mã nguồn (như thư mục `.git`) hoặc thông tin đăng nhập (như file `.env`). Mặc dù CIS Benchmark 2.5.3 đánh giá là thủ công (Manual), nhưng việc tự động hóa kiểm tra bằng AST parser giúp tăng cường độ tin cậy. Các trường hợp ngoại lệ như `.well-known` phục vụ cho SSL/TLS cũng được đảm bảo kiểm tra kỹ lưỡng, hỗ trợ cơ chế Auto-Remediation chèn luật chặn một cách an toàn mà không làm hỏng quy trình cấp phát chứng chỉ số của Let's Encrypt.
