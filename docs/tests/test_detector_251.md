# Tài liệu Kiểm thử: CIS Benchmark 2.5.1 (Detector 251)

**Mục tiêu:** Đảm bảo chỉ thị `server_tokens` được cấu hình là `off` để ẩn thông tin phiên bản NGINX và hệ điều hành, giúp giảm thiểu rủi ro bị kẻ tấn công thu thập thông tin (reconnaissance).

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector251` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa cụm từ khóa `"server_tokens"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 4 Test Cases
Kiểm tra các chỉ thị hợp lệ và được phép. Trong các trường hợp này, hàm `evaluate()` bắt buộc phải trả về `None` (không phát hiện vi phạm).
- **Chỉ thị `server_tokens` được tắt rõ ràng (1 test case):** Cấu hình `server_tokens off;` (có giá trị là `off`).
- **Khối `http` hợp lệ (1 test case):** Khi duyệt qua khối `http`, nếu bên trong đã có chứa chỉ thị `server_tokens` (bất kể giá trị gì, vì việc bắt lỗi giá trị sai đã được xử lý ở mức chỉ thị đơn lẻ), hàm sẽ bỏ qua và không yêu cầu thêm mới để tránh trùng lặp.
- **Không phải chỉ thị mục tiêu (2 test cases):** Các chỉ thị khác không liên quan như `server_name`, `listen` sẽ bị hàm này bỏ qua một cách an toàn mà không sinh ra lỗi.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 8 Test Cases
Kiểm tra các cấu hình vi phạm nguyên tắc bảo mật. Hàm `evaluate()` phải trả về một đối tượng chứa dữ liệu vi phạm và hướng khắc phục tương ứng.
- **Trường hợp cấu hình sai rõ ràng (Explicitly incorrect) (3 test cases):**
  - Cấu hình `server_tokens on;`
  - Cấu hình `server_tokens build;` (đối với phiên bản thương mại NGINX Plus).
  - Cấu hình `server_tokens ""` (rỗng hoặc giá trị bất kỳ khác `off`).
- **Trường hợp thiếu cấu hình (Missing configuration) (1 test case):**
  - Khối `http` không chứa bất kỳ chỉ thị `server_tokens` nào bên trong. (Mặc định của NGINX là `on` nếu không cấu hình, vi phạm chuẩn CIS).
- **Kiểm tra cấu trúc dữ liệu phản hồi đối với hành động Replace (2 test cases):**
  - Trả về đúng `file` và `exact_path`.
  - Hành động khắc phục bắt buộc là `"replace"`, `directive` là `"server_tokens"`, và tham số `args` được cập nhật thành `["off"]`.
- **Kiểm tra cấu trúc dữ liệu phản hồi đối với hành động Add (2 test cases):**
  - Trả về đúng `file` và vị trí `exact_path` cộng thêm cấp độ `["block"]` để trỏ vào bên trong khối `http`.
  - Hành động khắc phục bắt buộc là `"add"`, `directive` là `"server_tokens"`, và tham số `args` là `["off"]`.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 10 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST (từ `crossplane`), quét lỗi và gom nhóm kết quả.
- **Cấu hình an toàn (3 test cases):**
  - File cấu hình có khối `http` chứa `server_tokens off;`.
  - File cấu hình trống (`config: []`).
  - File cấu hình chứa nhiều ngữ cảnh khác nhau nhưng không vi phạm.
  *(Tất cả đều phải trả về mảng rỗng `[]`)*
- **Xử lý vi phạm thay thế (Replace) (2 test cases):** Đảm bảo hệ thống phát hiện chính xác `server_tokens on;` nằm ở khối cấu hình cục bộ và tạo hành động `"replace"` với giá trị `"off"`.
- **Xử lý vi phạm thêm mới (Add) (2 test cases):** Đảm bảo hệ thống phát hiện khối `http` thiếu cấu hình `server_tokens`, tạo hành động `"add"` để bổ sung vào cấp độ cao nhất bên trong khối `http`.
- **Gom nhóm lỗi (Grouping) (1 test case):** Nếu có nhiều vi phạm trong cùng một file (ví dụ: nhiều khối `server` lẻ tẻ cấu hình sai `server_tokens`), chúng phải được gom lại thành một kết quả duy nhất chứa danh sách nhiều `remediations`.
- **Nhiều file cấu hình (2 test cases):**
  - Hệ thống quét nhiều file và trả về kết quả quét chính xác cho từng file tương ứng.
  - File hợp lệ sẽ không bị xuất hiện trong báo cáo, chỉ có file chứa lỗi vi phạm bị đánh dấu.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector251` được thiết kế chặt chẽ nhằm đảm bảo mọi luồng logic quan trọng đều được kiểm chứng:
- **Tổng số lượng test cases dự kiến:** **25 test cases**
- **Độ bao phủ code (Line Coverage mục tiêu):** **100%** (do logic của detector này khá tập trung vào xử lý chỉ thị `server_tokens` và khối `http`).
- **Phân tích:** Các bài kiểm tra bao phủ toàn diện từ phần kiểm tra siêu dữ liệu, xử lý các trường hợp vi phạm do cấu hình giá trị sai (`replace`), vi phạm do thiếu cấu hình bắt buộc trong khối `http` (`add`), cho đến giả lập đường ống dữ liệu AST hoàn chỉnh thông qua hàm `scan()`. Điều này đảm bảo tính năng phát hiện và vá lỗi tự động cho `server_tokens` hoạt động an toàn và chính xác tuyệt đối.