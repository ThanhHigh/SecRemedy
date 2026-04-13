# Tài liệu Kiểm thử: CIS Benchmark 2.5.3 (Detector 253)

**Mục tiêu:** Đảm bảo việc cung cấp các file và thư mục ẩn (bắt đầu bằng dấu chấm, ví dụ: `.git`, `.env`) bị vô hiệu hóa (chuẩn CIS Benchmark 2.5.3). Các file ẩn thường chứa metadata nhạy cảm, lịch sử phiên bản hoặc cấu hình môi trường. Việc NGINX phục vụ các file này có thể làm lộ thông tin quan trọng (như thông tin đăng nhập database, mã nguồn), dẫn đến rủi ro bị tấn công toàn diện. Hệ thống sử dụng thư viện `crossplane` để phân tích đệ quy cấu hình NGINX, kiểm tra ngữ cảnh `server` để đảm bảo có khối `location` ngăn chặn quyền truy cập vào các file ẩn (ví dụ: `location ~ /\. { deny all; }`), và lưu ý việc xử lý ngoại lệ cho Let's Encrypt (`.well-known`).

---

## 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 4 Test Cases
Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector253` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.
- **ID (1 test case):** Kiểm tra ID của detector phải là `"2.5.3"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Ensure hidden file serving is disabled (Manual)"`).
- **Mức độ (1 test case):** Phải được gán cho Level 1 (Webserver, Proxy, Loadbalancer).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

---

## 2. Kiểm thử hàm `evaluate()`: Các trường hợp tuân thủ (Compliant Cases) - 24 Test Cases
Kiểm tra các khối cấu hình tuân thủ việc thiết lập block `location` ngăn chặn truy cập file ẩn. Hàm kiểm tra không phát hiện vi phạm (trả về `None`).
- **Thiết lập an toàn tại khối `server` (6 test cases):** Các trường hợp cấu hình chi tiết định nghĩa `location ~ /\. { deny all; }` (hoặc `return 404;`) ở từng block `server` cụ thể để chặn truy cập file ẩn.
- **Sử dụng include snippet cho cấu hình bảo mật (6 test cases):** Đảm bảo block `server` có chứa chỉ thị `include` gọi tới một file snippet tái sử dụng, trong đó có chứa luật ngăn chặn file ẩn hợp lệ.
- **Có ngoại lệ an toàn cho Let's Encrypt (6 test cases):** Cấu hình chặn file ẩn (`location ~ /\.`) nhưng có đặt ngoại lệ ưu tiên hợp lệ cho thư mục `.well-known/acme-challenge` (ví dụ: `location ^~ /.well-known/acme-challenge/ { allow all; }`), đảm bảo quá trình xác thực chứng chỉ không bị hỏng.
- **Kết hợp với các chỉ thị location phức tạp khác (6 test cases):** Khối `location` ẩn nằm cùng với các cấu hình phức tạp khác trong `server` block mà bộ quét vẫn hiểu và đánh giá đúng luật.

---

## 3. Kiểm thử hàm `evaluate()`: Các trường hợp vi phạm (Non-Compliant Cases) - 22 Test Cases
Kiểm tra các cấu hình thiếu sót khiến NGINX tiếp tục phục vụ các file ẩn, kích hoạt cảnh báo vi phạm để chuyển dữ liệu JSON Contract cho module Auto-Remediation (Thành viên 2).
- **Không khai báo `location` chặn file ẩn (Implicitly default) (6 test cases):** Khối `server` hoàn toàn không có block `location` nào sử dụng regex `~ /\.`. NGINX mặc định sẽ phục vụ các file này nếu chúng tồn tại trên web root. Đây là vi phạm phổ biến nhất.
- **Khai báo sai cú pháp hoặc chặn không triệt để (5 test cases):** Có cấu hình `location` chặn dấu chấm nhưng dùng regex sai, hoặc bên trong thiếu `deny all;` hay `return` (ví dụ: dùng `allow all` thay vì chặn).
- **Ngoại lệ bị đặt sai thứ tự (4 test cases):** Khối ngoại lệ Let's Encrypt được đặt nhưng do dùng regex không ưu tiên khiến cho thứ tự phân giải bị đè bởi block bắt file ẩn chung, dẫn đến rủi ro chặn Let's Encrypt hoặc để lọt file nhạy cảm.
- **Kiểm tra cấu trúc dữ liệu phản hồi JSON Contract (7 test cases):**
  - **`file`:** Phải trả về đúng đường dẫn file cấu hình NGINX chứa khối `server` cần bổ sung.
  - **`remediations`:** Phải là một list chứa đối tượng khắc phục.
  - **`action`:** Chủ yếu là `"add_block"` hoặc `"insert_block"` (thêm khối `location` mới).
  - **`directive`:** Mục tiêu là khối `"location"`.
  - **`value`:** Giá trị mong muốn (ví dụ: block location mẫu với `deny all;`).
  - **`context`:** Phải chứa đối tượng định vị chính xác vị trí AST (ví dụ: node của khối `server`) để công cụ diff/Dry-Run có thể hoạt động chính xác.

---

## 4. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 20 Test Cases
Các bài test kiểm tra tích hợp toàn diện thông qua việc mô phỏng dữ liệu phân tích AST đệ quy từ `crossplane` trên toàn bộ thư mục NGINX.
- **Cấu hình an toàn trên toàn bộ hệ thống đa server (3 test cases):** Hệ thống bao gồm nhiều file `conf.d/*.conf`, tất cả các `server` block đều có khai báo luật chặn file ẩn. *(Hệ thống trả về mảng rỗng `[]`)*
- **Nhận diện sự vắng mặt của chỉ thị ở hệ thống đa tệp (3 test cases):** Phân tích toàn bộ cây thư mục và phát hiện một số virtual host (`server` block) trong `conf.d/` không tự định nghĩa block `location` chặn file ẩn.
- **Gom nhóm lỗi (Grouping) và cảnh báo (3 test cases):** Phân biệt chính xác virtual host nào bị lỗi và khoanh vùng chính xác file bị lỗi mà không báo nhầm các server block an toàn.
- **Xử lý các ngoại lệ cấu hình (3 test cases):** Xử lý an toàn khi file cấu hình hoàn toàn trống, hoặc chỉ chứa block không liên quan (như `http`, `stream` không có `server`), đảm bảo logic quét không bị gián đoạn.
- **Tương tác với Include Directive phức tạp (5 test cases):** Khả năng đệ quy `crossplane` (ví dụ: `nginx.conf` -> `include conf.d/*` -> định nghĩa `server`). Nếu `server` block trong file con thiếu block `location` ẩn, báo cáo phải trỏ đúng file con đó.
- **Tính toàn vẹn của kết quả Schema cho Auto-Remediation (3 test cases):** Đảm bảo JSON Contract do Thành viên 1 tạo ra cung cấp tọa độ dòng chính xác để Thành viên 2 chèn khối `location ~ /\. { deny all; }` vào cấu hình. Việc này đòi hỏi AST định vị đúng khối `server` để sửa chữa, cho phép lệnh `nginx -t` kiểm tra cấu trúc ngoặc sau khi Dry-Run.

---

## 5. Độ bao phủ của bộ test (Test Coverage)
Bộ test cases cho `Detector253` được thiết kế chặt chẽ nhằm bảo vệ máy chủ khỏi nguy cơ rò rỉ mã nguồn và metadata nền tảng, bám sát các tiêu chí của đồ án tốt nghiệp:
- **Tổng số lượng test cases:** **70 test cases** (4 + 24 + 22 + 20)
- **Độ bao phủ code dự kiến (Line Coverage):** **> 94%**
- **Phân tích (Context Đồ án):** Tương tự CIS 2.5.2, CIS 2.5.3 tập trung vào việc xử lý trường hợp **"thiếu sót"** (missing block). NGINX mặc định không cấm truy cập file ẩn, nên Scanner (Thành viên 1) phải tìm kiếm sự vắng mặt của block `location` ẩn trong toàn bộ các khối `server`. JSON Contract sinh ra phải hướng dẫn rõ ràng cho module Auto-Remediation (Thành viên 2) chèn thêm chỉ thị `"add_block"` một cách an toàn mà không phá vỡ cú pháp hoặc ảnh hưởng tới chứng chỉ Let's Encrypt hiện hữu. Điều này giúp hệ thống tự động hoàn thiện cấu hình mà vẫn đảm bảo tính ổn định (Zero-Downtime) sau khi chạy `nginx -t`.