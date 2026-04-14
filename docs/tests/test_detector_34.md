# Tài liệu Kiểm thử: CIS Benchmark 3.4 (Detector 34)

**Mục tiêu:** Đảm bảo khi NGINX hoạt động ở vai trò reverse proxy hoặc load balancer, nó phải truyền thông tin IP thực của client thông qua các header chuẩn như `X-Forwarded-For` và `X-Real-IP` (chuẩn CIS Benchmark 3.4). Việc thiếu cấu hình này khiến ứng dụng backend chỉ thấy IP của NGINX proxy, gây khó khăn cho việc kiểm toán bảo mật, phản ứng sự cố và kiểm soát truy cập. Hệ thống sử dụng thư viện `crossplane` để phân tích đệ quy cấu hình NGINX, kiểm tra các khối `server` hoặc `location` có sử dụng chỉ thị `proxy_pass` để đảm bảo có cấu hình `proxy_set_header X-Forwarded-For` và `proxy_set_header X-Real-IP` đi kèm.

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector34` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"3.4"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure proxies pass source IP information"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 - Proxy, Level 1 - Loadbalancer.
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các khối cấu hình chứa `proxy_pass` có tuân thủ việc thiết lập truyền IP thật qua `proxy_set_header`. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Thiết lập an toàn tại khối `location` (6 test cases):** Các cấu hình khai báo rõ ràng các chỉ thị `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` và `proxy_set_header X-Real-IP $remote_addr;` ngay trong khối `location` chứa `proxy_pass`.
- **Thiết lập an toàn tại khối `server` hoặc `http` (6 test cases):** Các trường hợp cấu hình định nghĩa các header proxy ở cấp độ `server` hoặc `http` để các khối `location` con có chứa `proxy_pass` được kế thừa tự động.
- **Kiểm tra lồng ghép đệ quy và cấu hình location tương ứng (Nested Contexts) (6 test cases):** Trình phân tích xác nhận rằng khi có `location` lồng nhau chứa `proxy_pass`, các thiết lập `proxy_set_header` ở cấp cha hoặc trực tiếp trong cấp con vẫn được áp dụng hợp lệ.
- **Kết hợp với các chỉ thị bảo mật khác (6 test cases):** Chỉ thị nằm xen kẽ giữa các cấu hình phức tạp (ví dụ: đứng cùng `proxy_set_header Host $host`, `proxy_hide_header`, v.v.) mà không làm ảnh hưởng đến logic phân tích của thư viện `crossplane`.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình có `proxy_pass` nhưng thiếu hoặc sai cấu hình truyền IP thật, kích hoạt cảnh báo vi phạm để chuyển dữ liệu JSON Contract cho module Auto-Remediation (Thành viên 2).
- **Không khai báo `proxy_set_header` cần thiết (Implicitly default) (6 test cases):** Khối `location` có sử dụng `proxy_pass` nhưng hoàn toàn thiếu việc thiết lập header `X-Forwarded-For` và `X-Real-IP`. Đây là vi phạm phổ biến nhất.
- **Khai báo thiếu một trong các header quan trọng (5 test cases):** Quản trị viên cấu hình truyền `X-Real-IP` nhưng quên cấu hình `X-Forwarded-For`, hoặc ngược lại, khiến hệ thống backend vẫn bị thiếu thông tin truy vết đầy đủ.
- **Cấu hình `proxy_set_header` sai giá trị (4 test cases):** Kiểm tra các dạng cấu hình có khai báo header nhưng truyền sai biến số (ví dụ truyền chuỗi tĩnh thay vì `$remote_addr` hoặc `$proxy_add_x_forwarded_for`).
- **Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình NGINX chứa khối `location` hoặc `server` cần bổ sung.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Do thiếu cấu hình, action chủ yếu là `"add"` hoặc `"insert"` (thêm các dòng `proxy_set_header` mới).
  - **`directive`:** Mục tiêu là chỉ thị `"proxy_set_header"`.
  - **`value`:** Giá trị mong muốn (ví dụ: `"X-Forwarded-For $proxy_add_x_forwarded_for"` hoặc `"X-Real-IP $remote_addr"`).
  - **`context`:** Phải chứa đối tượng định vị chính xác vị trí AST (ví dụ: node của khối `location` chứa `proxy_pass`) để công cụ diff/Dry-Run của Thành viên 2 có thể chèn đúng chỗ một cách tự động.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy từ `crossplane` trên toàn bộ thư mục NGINX.
- **Cấu hình an toàn trên toàn bộ hệ thống (3 test cases):** Hệ thống bao gồm nhiều file `conf.d/*.conf`, các khối `location` có `proxy_pass` đều được đi kèm đầy đủ các header `X-Forwarded-For` và `X-Real-IP`. *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases):** Phân tích toàn bộ cây thư mục và phát hiện một số `location` block trong các file cấu hình API phân tán thiếu việc truyền header IP.
- **Gom nhóm lỗi (Grouping) và cảnh báo ghi đè (3 test cases):** Nếu cấp `server` đã thiết lập proxy header, nhưng một `location` cụ thể vô tình định nghĩa lại `proxy_set_header` khác (ví dụ `Host`) mà không định nghĩa lại các header IP (do NGINX sẽ xóa kế thừa nếu cấp dưới có định nghĩa cùng chỉ thị), Scanner phải phát hiện và khoanh vùng chính xác lỗi do mất kế thừa này.
- **Xử lý các ngoại lệ cấu hình (3 test cases):** Xử lý an toàn khi phân tích các file không sử dụng tính năng proxy (không có `proxy_pass`), Scanner phải bỏ qua mà không báo lỗi sai (false positive).
- **Tương tác với Include Directive phức tạp (5 test cases):** Khả năng đệ quy `crossplane` qua nhiều tầng `include` (ví dụ: `include proxy_params;`). Nếu file `proxy_params` được include trong `location` mà thiếu các header chuẩn, hệ thống phải truy vết và chỉ ra đúng nơi cần sửa.
- **Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases):** Đảm bảo JSON Contract do Thành viên 1 tạo ra cung cấp tọa độ dòng chính xác để Thành viên 2 chèn các dòng `proxy_set_header` vào cấu hình NGINX. Việc này đòi hỏi AST định vị đúng khối lồng nhau để sửa chữa, cho phép lệnh `nginx -t` xác nhận cú pháp an toàn sau khi Dry-Run.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector34` được thiết kế chặt chẽ nhằm bảo vệ máy chủ proxy khỏi nguy cơ mất dấu IP thực của client, bám sát các tiêu chí của đồ án tốt nghiệp DevSecOps:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích (Context Đồ án):** CIS 3.4 tập trung vào việc bổ sung các chỉ thị còn thiếu trong ngữ cảnh proxy. Vì vậy, Scanner (Thành viên 1) phải tìm kiếm sự xuất hiện của `proxy_pass` trước tiên và kiểm tra sự vắng mặt của các header bắt buộc đi kèm. JSON Contract sinh ra phải hướng dẫn rõ ràng cho module Auto-Remediation (Thành viên 2) chèn thêm chỉ thị `"add"` một cách an toàn mà không phá vỡ cú pháp. Đặc biệt, việc xử lý logic ghi đè (override) kế thừa của NGINX đối với chỉ thị `proxy_set_header` cũng được chú trọng để đảm bảo tính chính xác, giúp hệ thống tự động hoàn thiện cấu hình proxy an toàn (Zero-Downtime) sau khi chạy `nginx -t`.