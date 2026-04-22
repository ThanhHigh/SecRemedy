# Tài liệu Kiểm thử: Detector 34 (CIS Nginx Benchmark - Recommendation 3.4)

## Tổng quan về Recommendation 3.4 trong CIS Nginx Benchmark:

Đảm bảo các proxy chuyển tiếp thông tin IP nguồn.
Khi NGINX hoạt động như một reverse proxy hoặc load balancer, mặc định máy chủ upstream chỉ thấy địa chỉ IP nội bộ của NGINX, làm ẩn IP gốc của client. Các HTTP header tiêu chuẩn như `X-Forwarded-For` và `X-Real-IP` phải được cấu hình rõ ràng để chuyển tiếp địa chỉ IP và giao thức của client cho ứng dụng backend. Việc này đặc biệt quan trọng đối với điều tra sự cố (Forensics), kiểm soát truy cập (Access Control) và tuân thủ (Compliance).

## Tổng quan về Detector 34

### Mục tiêu của Detector 34

Kiểm tra sự hiện diện của các cấu hình chuyển tiếp IP nguồn. Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane. Detector sẽ tìm kiếm các khối cấu hình (thường là `location`) có chứa các chỉ thị proxy như `proxy_pass`, `fastcgi_pass`, hoặc `grpc_pass`. Tại các khối này (hoặc được kế thừa từ `server`, `http`), phải có khai báo `proxy_set_header X-Forwarded-For` và `proxy_set_header X-Real-IP` (hoặc `fastcgi_param` tương ứng). Đầu ra là danh sách các `uncompliances` (JSON). Nếu thiếu một hoặc cả hai header, trả về lỗi kèm hành động `add` để Auto-Remediation tự động chèn thêm cấu hình header bị thiếu.

### Cách hoạt động của Detector 34 dựa trên BaseRecom

Detector kế thừa `BaseRecom`, sử dụng `traverse_directive` để duyệt qua toàn bộ cây AST. Đầu tiên, nó tìm các chỉ thị định tuyến proxy (vd: `proxy_pass`, `fastcgi_pass`). Sau đó, tại ngữ cảnh logic chứa proxy, detector kiểm tra xem có tồn tại (hoặc kế thừa) cấu hình `proxy_set_header` cho `X-Forwarded-For` và `X-Real-IP` hay không. Lưu ý về cơ chế kế thừa của Nginx: nếu một khối `location` định nghĩa một `proxy_set_header` bất kỳ (vd: `Host`), nó sẽ làm mất kế thừa các `proxy_set_header` từ `server` hay `http`. Nếu phát hiện thiếu, vi phạm sẽ được ghi nhận. Hệ thống sử dụng `_group_by_file` để gộp vi phạm theo file.

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_34.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                              |
| :------------------------------------------------------------------- | :--------------------- | :---------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc  |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra xử lý AST và phát hiện thiếu IP Header |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `Detector34` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"3.4"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"Đảm bảo các proxy chuyển tiếp thông tin IP nguồn"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc phát hiện cấu hình thiếu proxy header thông qua JSON AST từ `crossplane`.

- **Hợp lệ - Cấu hình Proxy đúng chuẩn (Valid Configuration) - 10 Test Cases:**
  1. `location` chứa `proxy_pass` và định nghĩa đủ cả 2 header `X-Forwarded-For`, `X-Real-IP`.
  2. Kế thừa từ `server`: Cả 2 header định nghĩa ở khối `server`, `location` chứa `proxy_pass` (không định nghĩa header khác).
  3. Kế thừa từ `http`: Cả 2 header định nghĩa ở khối `http`, `location` chứa `proxy_pass` (không định nghĩa header khác).
  4. `fastcgi_pass` đi kèm đủ tham số cấu hình chuyển tiếp IP hợp lệ.
  5. `grpc_pass` đi kèm đủ tham số cấu hình chuyển tiếp IP hợp lệ.
  6. Có nhiều `location` sử dụng `proxy_pass`, tất cả đều có cấu hình header đủ và đúng.
  7. Cấu hình `proxy_set_header` sử dụng biến hợp lệ (ví dụ: `$proxy_add_x_forwarded_for` cho `X-Forwarded-For` và `$remote_addr` cho `X-Real-IP`).
  8. Khối `location` hoàn toàn không sử dụng proxy (chỉ trả về file tĩnh) -> Hợp lệ do không thuộc phạm vi bắt buộc.
  9. Kế thừa hỗn hợp: Một header kế thừa từ `http`, header còn lại định nghĩa ở khối `location`.
  10. Lệnh `proxy_pass` nằm trong khối `if` bên trong `location` và cấu hình 2 header được thiết lập đúng.

- **Không hợp lệ - Thiếu thông tin IP nguồn (Missing Proxy Headers) - 15 Test Cases:**
  - 11. `location` có `proxy_pass` nhưng không khai báo bất kỳ `proxy_set_header` nào.
  - 12. `location` có `proxy_pass`, có `X-Forwarded-For` nhưng thiếu `X-Real-IP`.
  - 13. `location` có `proxy_pass`, có `X-Real-IP` nhưng thiếu `X-Forwarded-For`.
  - 14. `fastcgi_pass` thiếu tham số chuyển tiếp IP nguồn (cần kiểm tra `fastcgi_param`).
  - 15. `grpc_pass` thiếu cấu hình chuyển tiếp `grpc_set_header`.
  - 16. Header `X-Real-IP` bị viết sai lỗi chính tả (vd: `X-RealIP`).
  - 17. Khối `server` có nhiều `location` dùng `proxy_pass`, nhưng một trong số đó bị thiếu header.
  - 18. **Mất kế thừa:** Khối `server` đã khai báo đủ 2 header, nhưng khối `location` có `proxy_pass` lại định nghĩa thêm một `proxy_set_header Host $host;` mà không lặp lại 2 header chuyển tiếp IP (Nginx ghi đè hoàn toàn).
  - 19. Khối `http` đã khai báo đủ 2 header, nhưng khối `location` định nghĩa một header proxy khác gây mất kế thừa.
  - 20. Khối nested `location` chứa `proxy_pass` và bị thiếu header.
  - 21. `proxy_pass` nằm trực tiếp ở khối `server` (không khuyến khích) và thiếu header.
  - 22. Header `X-Forwarded-For` bị vô hiệu hóa một cách rõ ràng (vd: `proxy_set_header X-Forwarded-For "";`).
  - 23. `location` chứa nhiều lệnh `proxy_pass` (do nhiều nhánh `if` hoặc lỗi cấu hình) và đều thiếu header.
  - 24. `location` có proxy nhưng cả 2 header dùng chung một sai lầm phổ biến nào đó không thỏa mãn luật.
  - 25. Có khai báo `proxy_set_header` nhưng tham số bị thiếu hoặc rỗng.

- **Cấu hình đa tệp (Multi-file configurations) - 10 Test Cases:**
  - 26. `nginx.conf` chứa `include conf.d/app.conf;`. Tại `app.conf`, `proxy_pass` bị thiếu cấu hình header.
  - 27. `nginx.conf` khai báo đủ header ở khối `http`. File `app.conf` định nghĩa `proxy_pass` mà không bị mất kế thừa -> Hợp lệ.
  - 28. Giống câu 27, nhưng `app.conf` chứa `proxy_set_header Host` làm mất kế thừa từ `http` -> Vi phạm ở `app.conf`.
  - 29. Bao gồm nhiều file conf, chỉ có một file có `proxy_pass` bị thiếu header chuyển tiếp IP.
  - 30. File include nằm ở cấp độ `location` chứa `proxy_pass` và thiếu header.
  - 31. `app.conf` khai báo header ở khối `server`, khối `location` bên trong sử dụng `proxy_pass` kế thừa hợp lệ -> Hợp lệ.
  - 32. Lỗi được định danh đúng `file` (báo cáo vào `app.conf` thay vì `nginx.conf`) khi payload chỉ ra nơi thiếu.
  - 33. Cấu hình `proxy_pass` nằm ở một file, và `include proxy_params.conf;` nằm ở vị trí khác, nhưng file include đó thiếu header `X-Real-IP`.
  - 34. `proxy_pass` nằm trong file `api.conf` được include bởi `app.conf` (level 2 include), thiếu header.
  - 35. Hai file include khác nhau cùng định nghĩa thiếu header cho 2 `location` dùng `proxy_pass` riêng biệt.

- **Kiểm tra Payload Remediation và Ngoại lệ cấu trúc (Remediation & Edge Cases) - 7 Test Cases:**
  - 36. Payload cho khối thiếu cả 2 header: Trả về một hoặc nhiều hành động `add` cho cả `X-Forwarded-For` và `X-Real-IP` vào đúng `exact_path`.
  - 37. Payload cho khối chỉ thiếu 1 header (vd: `X-Real-IP`): Chỉ trả về hành động `add` đối với header bị thiếu.
  - 38. `exact_path` chỉ định chính xác khối `block` của `location` để Auto-Remediation có thể `add` lệnh `proxy_set_header` vào trong cấu trúc JSON.
  - 39. Toàn bộ AST rỗng hoặc không có bất kỳ lệnh proxy nào -> Hợp lệ.
  - 40. Các header chuyển tiếp IP nằm trong block comment (Crossplane bỏ qua), AST trả về không có -> Bị phát hiện là thiếu và trả về action `add`.
  - 41. Trả về payload với logical context thể hiện đúng cấp bậc (vd: `['http', 'server', 'location']`).
  - 42. Gom nhóm hành động (multiple remediation actions) cho cùng một block `location` hợp lý khi gộp theo `file`.
