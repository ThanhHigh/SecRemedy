# Tài liệu Kiểm thử: CIS Benchmark 2.4.1 (Detector 241)

**Mục tiêu:** Đảm bảo NGINX chỉ lắng nghe các kết nối mạng trên các cổng được ủy quyền (ví dụ: 80, 443, 8080, 3000).

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector241` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.4.1"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa cụm từ khóa `"authorized ports"`.
- **Cổng được ủy quyền (1 test case):** Danh sách cổng mặc định phải chứa `"80"` và `"443"`.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các chỉ thị hợp lệ và được phép. Trong các trường hợp này, hàm `evaluate()` bắt buộc phải trả về `None` (không phát hiện vi phạm).
- **Cổng được ủy quyền dạng số (4 test cases):** 80, 443 (kèm tham số `default_server`), 8080, 3000.
- **Cổng được ủy quyền kèm thông số SSL/QUIC (2 test cases):** `443 ssl`, `443 quic`.
- **Định dạng IPv4:port (5 test cases):** `127.0.0.1:80`, `0.0.0.0:443`, `127.0.0.1:8080`, `127.0.0.1:3000 default_server`, `192.168.1.10:443`.
- **Định dạng IPv6:port (3 test cases):** `[::]:80`, `[::]:443`, `[::1]:443`.
- **Unix socket (2 test cases):** `unix:/run/nginx.sock` (kể cả có thêm đuôi cấu hình, bị bỏ qua vì đây không phải là một cổng mạng).
- **Giá trị hostname / ký tự đại diện (2 test cases):** `localhost`, `*` (NGINX tự động mặc định các giá trị này sử dụng cổng 80, do đó hợp lệ).
- **Chỉ thị rỗng (1 test case):** Bỏ qua một cách an toàn mà không bị lỗi.
- **Không phải chỉ thị `listen` (2 test cases):** Các chỉ thị khác như `server_name`, `root` sẽ bị hàm này bỏ qua.
- **Chỉ thị `listen` nằm sai ngữ cảnh (3 test cases):** Các cấu hình `listen` nhưng lại nằm trong danh sách ngữ cảnh rỗng, nằm trong khối `events`, hoặc chỉ ở khối `http` (chưa vào `server`) đều bị bỏ qua an toàn.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 15 Test Cases
Kiểm tra các chỉ thị chứa các cổng mạng không được cấp phép. Trong trường hợp này, hàm `evaluate()` phải trả về một đối tượng chứa dữ liệu vi phạm và hướng khắc phục.
- **Cổng không được ủy quyền dạng số (5 test cases):** 8089, 8443 (kèm `default_server`), 3099, 22, 9090.
- **Định dạng IPv4:port với cổng không hợp lệ (2 test cases):** `127.0.0.1:8089`, `192.168.0.1:3099`.
- **Định dạng IPv6:port với cổng không hợp lệ (2 test cases):** `[::]:8089`, `[::1]:9090`.
- **Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file chứa vi phạm.
  - **`remediations`:** Phải là một list và chứa đối tượng khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"delete"`.
  - **`directive`:** Tên chỉ thị phải là `"listen"`.
  - **`context`:** Phải lưu giữ và trả về chính xác mảng vị trí AST (`exact_path`) (kiểm tra cả theo tham chiếu/reference) đã truyền vào để phục vụ cho tính năng vá tự động sau này.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST (từ `crossplane`), quét lỗi và gom nhóm kết quả.
- **Cấu hình an toàn (4 test cases):**
  - Khối cấu hình chỉ toàn các cổng hợp lệ.
  - File cấu hình trống (`config: []`).
  - File cấu hình chỉ dùng Unix Socket.
  - File cấu hình có phần mở rộng không hợp lệ (không phải `.conf`).
  *(Tất cả đều phải trả về mảng rỗng `[]`)*
- **Xử lý vi phạm đơn lẻ (4 test cases):** Đảm bảo hệ thống phát hiện chính xác lỗi, file path hợp lệ, tên `directive` chuẩn xác và action là `"delete"`.
- **Gom nhóm lỗi (Grouping) (2 test cases):** Nếu có 2 hoặc 3 lỗi vi phạm trong cùng một file, chúng phải được gom lại thành một kết quả duy nhất chứa danh sách nhiều `remediations`.
- **Hỗn hợp cổng đúng và sai (2 test cases):** Nếu một `server` lắng nghe trên cổng 80 (hợp lệ) và 8089 (vi phạm), kết quả chỉ trả về vi phạm cho cổng sai mà không ảnh hưởng tới cổng đúng.
- **Nhiều file cấu hình (2 test cases):**
  - Hệ thống quét 2 file đều vi phạm và trả về kết quả quét chính xác cho từng file tương ứng.
  - File hợp lệ sẽ không bị xuất hiện trong báo cáo, chỉ có file chứa lỗi vi phạm bị đánh dấu (một file clean và một file dirty).
- **Bỏ qua chỉ thị `listen` do dương tính giả (3 test cases):** Các chỉ thị `listen` rác nằm trong khối `http`, `events` hoặc ở cấp độ ngoài cùng (top-level) đều bị bỏ qua không tạo ra cảnh báo.
- **Vi phạm trên IPv6 (1 test case):** Đảm bảo `scan()` lấy và phân tích đúng trường hợp IPv6 với cổng sai.
- **Tính toàn vẹn của kết quả Schema (2 test cases):** Xác nhận lại đối tượng kết quả `scan()` phải chứa đầy đủ các khoá dữ liệu yêu cầu: `file`, `remediations` (chứa `action`, `directive`, `context`).

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector241` được thiết kế chặt chẽ nhằm đảm bảo mọi luồng logic quan trọng đều được kiểm chứng:
- **Tổng số lượng test cases:** **63 test cases**
- **Độ bao phủ code (Line Coverage):** **94%** (với 33/35 dòng code được thực thi trong quá trình chạy test).
- **Phân tích:** Các bài kiểm tra đã bao phủ toàn diện từ kiểm tra siêu dữ liệu, xử lý các trường hợp tham số cổng mạng hợp lệ và không hợp lệ trong `evaluate()`, cho đến giả lập đường ống dữ liệu AST hoàn chỉnh thông qua hàm `scan()`. Điểm bao phủ cao (94%) cho thấy module sẵn sàng tích hợp an toàn vào công cụ quét NGINX cốt lõi và đáp ứng chính xác CIS Benchmark.