# Tài liệu Kiểm thử: CIS Benchmark 2.5.1 (Detector 251)

**Mục tiêu:** Đảm bảo chỉ thị `server_tokens` được cấu hình là `off` để ẩn thông tin phiên bản NGINX và hệ điều hành trong các trang báo lỗi và header phản hồi HTTP.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector251` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa cụm từ khóa `"server_tokens"`.
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 5 Test Cases

Kiểm tra các cấu hình hợp lệ khi `server_tokens` được đặt thành `off`. Hệ thống không phát hiện vi phạm (trả về `None` hoặc list rỗng).

- **Cấu hình chuẩn trong khối http (1 test case):** Khối `http` có `server_tokens off;`.
- **Cấu hình trong khối server và location (2 test cases):** Việc đặt `server_tokens off;` ở mức `server` hoặc `location` cũng là hợp lệ.
- **Các giá trị kế thừa hợp lệ (2 test cases):** Nếu khối `http` có `server_tokens off;` và các khối `server` con không định nghĩa lại (kế thừa), hệ thống phải đánh giá là an toàn.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 12 Test Cases

Kiểm tra các cấu hình thiếu an toàn, khi `server_tokens` không được cấu hình (mặc định là `on`) hoặc cấu hình sai.

- **Không khai báo `server_tokens` (2 test cases):** File cấu hình hoàn toàn không có chỉ thị `server_tokens` trong khối `http` hoặc file trống (mặc định là NGINX sẽ bật tính năng này).
- **Cấu hình `server_tokens on;` (3 test cases):** Chỉ thị được khai báo rõ ràng là `on` ở khối `http`, `server` hoặc `location`.
- **Sử dụng giá trị không phải `off` (2 test cases):** Cấu hình `server_tokens build;` (dành cho bản NGINX thương mại) hoặc chuỗi rỗng được coi là vi phạm nếu không ẩn hoàn toàn thông tin.
- **Ghi đè cấu hình không an toàn (1 test case):** Khối `http` có `server_tokens off;` nhưng một khối `server` cụ thể lại cấu hình `server_tokens on;`. Hệ thống phải phát hiện vi phạm ở khối `server` đó.
- **Kiểm tra cấu trúc dữ liệu phản hồi (4 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình chứa cấu hình sai hoặc file cần thêm cấu hình.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"replace"` (để chuyển `on` thành `off`) hoặc `"add"` (nếu chưa khai báo).
  - **`directive`:** Mục tiêu là `"server_tokens"`.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 8 Test Cases

Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST (từ `crossplane`), quét toàn bộ ngữ cảnh NGINX.

- **Cấu hình an toàn đầy đủ (1 test case):** Khối `http` tổng chứa `server_tokens off;` và không có khối con nào ghi đè sai. _(Hệ thống trả về mảng rỗng `[]`)_
- **Nhiều file cấu hình không an toàn (2 test cases):** Cấu hình chứa nhiều file `conf.d/*.conf` có `server_tokens on;` hoặc cấu hình đúng ở `http` nhưng file include lại sai. Hệ thống phải báo cáo vị trí cần thêm/sửa hợp lý.
- **Ưu tiên cấu hình khối `http` (1 test case):** Kiểm tra xem module quét có nhắm mục tiêu chính xác vào khối `http` trong file `nginx.conf` gốc để đưa ra đề xuất thêm mới hay không.
- **Chỉ thị bị comment (1 test case):** Cấu hình `# server_tokens off;` bị comment thì NGINX sẽ dùng mặc định là `on`, do đó hệ thống phải coi đây là trường hợp vi phạm và yêu cầu cấu hình rõ ràng.
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận đối tượng kết quả `scan()` chứa đầy đủ các khoá dữ liệu yêu cầu: `file`, `remediations` (chứa `action`, `directive`, `context`) hỗ trợ tự động thêm hoặc sửa đổi `server_tokens` thông qua auto-remediation.

---

## 5. Độ bao phủ của bộ test (Test Coverage)

Bộ test cases cho `Detector251` được thiết kế nhằm đảm bảo mọi luồng logic quan trọng đều được kiểm chứng:

- **Tổng số lượng test cases:** **29 test cases** (4 + 5 + 12 + 8)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Các bài kiểm tra đảm bảo hệ thống không chỉ tìm kiếm từ khóa `server_tokens` mà còn hiểu được bối cảnh kế thừa từ khối `http` xuống `server` và `location`. Việc phát hiện trường hợp thiếu chỉ thị (mặc định là không an toàn) và đưa ra hành động `"add"` hoặc `"replace"` chuẩn xác giúp công cụ đáp ứng nghiêm ngặt yêu cầu của CIS Benchmark 2.5.1 và bảo vệ NGINX khỏi việc rò rỉ thông tin phiên bản.
