# Tài liệu Kiểm thử: CIS Benchmark 3.4 (Detector 34)

**Mục tiêu:** Đảm bảo khi NGINX hoạt động như một reverse proxy hoặc load balancer (có sử dụng chỉ thị `proxy_pass`), cấu hình phải chuyển tiếp thông tin địa chỉ IP thực của client. Hệ thống phân tích cấu hình để đảm bảo các HTTP header như `X-Forwarded-For` và `X-Real-IP` được thiết lập rõ ràng thông qua chỉ thị `proxy_set_header`, nhằm hỗ trợ kiểm toán bảo mật, phản hồi sự cố và kiểm soát truy cập tại các ứng dụng backend.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector34` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"3.4"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề chứa nội dung liên quan đến việc chuyển tiếp thông tin IP nguồn (`"Ensure proxies pass source IP information"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục).

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các cấu hình hợp lệ khi có sử dụng `proxy_pass` kèm theo việc cấu hình đầy đủ các header chuyển tiếp IP. Hệ thống không phát hiện vi phạm (trả về `None`).
- **Khai báo tiêu chuẩn trong location (5 test cases):** Khối `location` có chứa `proxy_pass` và đồng thời có khai báo cả `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` và `proxy_set_header X-Real-IP $remote_addr;`.
- **Khai báo kế thừa từ khối server (5 test cases):** Các chỉ thị `proxy_set_header` được cấu hình ở cấp độ `server`, các khối `location` bên trong có sử dụng `proxy_pass` kế thừa cấu hình này một cách hợp lệ.
- **Khai báo kế thừa từ khối http (5 test cases):** Các chỉ thị `proxy_set_header` được cấu hình ở cấp độ `http`, áp dụng toàn cục cho mọi reverse proxy bên trong.
- **Vị trí file cấu hình include (4 test cases):** Các chỉ thị header được bao gồm (include) từ một file snippet chung, ví dụ `include proxy_params;` và hệ thống AST parser phân tích, xác nhận được nội dung file này chứa đầy đủ các header yêu cầu.
- **Sử dụng biến tùy chỉnh hợp lệ (5 test cases):** Cấu hình sử dụng các biến IP khác một cách an toàn và tương đương (ví dụ, truyền `$http_x_forwarded_for` nếu cấu hình phức tạp đằng sau một proxy khác) miễn là ý định chuyển tiếp IP được đảm bảo.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 20 Test Cases
Kiểm tra các cấu hình có sử dụng reverse proxy (`proxy_pass`) nhưng không cấu hình đầy đủ việc chuyển tiếp IP, dẫn đến backend chỉ nhìn thấy IP của NGINX.
- **Thiếu hoàn toàn header chuyển tiếp IP (5 test cases):** Khối `location` có sử dụng `proxy_pass` nhưng không có bất kỳ chỉ thị `proxy_set_header` nào liên quan đến `X-Forwarded-For` hay `X-Real-IP` (cả trong khối đó lẫn các khối cha).
- **Thiếu một trong các header quan trọng (5 test cases):** Cấu hình có thiết lập `X-Forwarded-For` nhưng lại thiếu `X-Real-IP`, hoặc ngược lại, không đạt đủ yêu cầu của benchmark.
- **Ghi đè bằng giá trị rỗng hoặc không hợp lệ (4 test cases):** Có định nghĩa `proxy_set_header X-Forwarded-For ""` hoặc thiết lập header bằng một giá trị tĩnh/cứng (hardcoded) làm mất đi IP thực của client.
- **Kiểm tra cấu trúc dữ liệu phản hồi (6 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình chứa khối vi phạm.
  - **`remediations`:** Phải là một list chứa đối tượng mô tả cách khắc phục.
  - **`action`:** Hành động khắc phục bắt buộc là `"add"` (để thêm chỉ thị header).
  - **`directive`:** Mục tiêu là `"proxy_set_header"`.
  - **`context`:** Phải xác định đúng block (thường là khối `location` chứa `proxy_pass` bị lỗi) cần chèn cấu hình khắc phục.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 15 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST từ `crossplane`, đảm bảo hệ thống quét chính xác trên toàn bộ ngữ cảnh cấu hình NGINX.
- **Cấu hình an toàn đầy đủ (3 test cases):**
  - Tất cả các khối `location` sử dụng `proxy_pass` trong các file `vhost` đều được bảo vệ bởi cấu hình `proxy_set_header` đầy đủ.
  - *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhiều file cấu hình vi phạm (3 test cases):** Quét thấy một số `location` có cấu hình header đầy đủ nhưng một số `location` khác trong cùng file hoặc file khác thì quên không cấu hình. Báo cáo cần chỉ đích danh các vị trí vi phạm.
- **Gom nhóm lỗi (Grouping) (3 test cases):** Nếu trong cùng một file cấu hình có nhiều khối `location` vi phạm thiếu header IP, hệ thống sẽ gom nhóm các lỗi này theo file và block một cách logic.
- **Bỏ qua các khối không sử dụng proxy (3 test cases):** Nếu khối `server` hoặc `location` chỉ phục vụ file tĩnh (`root`, `alias`) hoặc redirect (`return`), việc không có `proxy_set_header` là hoàn toàn bình thường và hệ thống không được báo lỗi sai (false positive).
- **Tính toàn vẹn của kết quả Schema (3 test cases):** Xác nhận đối tượng kết quả `scan()` chứa đầy đủ thông tin để module Auto-Remediation có thể bơm chính xác các dòng `proxy_set_header X-Real-IP $remote_addr;` và `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` vào các khối thiếu sót.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector34` được thiết kế chặt chẽ nhằm triệt tiêu rủi ro che giấu IP thực của client khi đi qua NGINX proxy:
- **Tổng số lượng test cases:** **63 test cases** (4 + 24 + 20 + 15)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích:** Việc chuyển tiếp chính xác IP của người dùng (client) là cực kỳ quan trọng trong kiến trúc microservices và phân tích log an ninh mạng. CIS Benchmark 3.4 yêu cầu mức độ Proxy/Loadbalancer phải tường minh về nguồn gốc truy cập. Bộ test này bao phủ cả những trường hợp kế thừa chỉ thị phức tạp của NGINX (từ `http` -> `server` -> `location`) cũng như rủi ro "bỏ quên" trong các `location` riêng rẽ, tạo tiền đề vững chắc cho việc Remediator chèn luật an toàn (thêm header) mà không làm hỏng cú pháp điều hướng hiện có.