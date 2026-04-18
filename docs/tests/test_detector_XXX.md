# Tài liệu Kiểm thử: Detector XXX (CIS Nginx Benchmark - Recommendation XXX)

## Tổng quan về Recommendation XXX trong CIS Nginx Benchmark:

[Mô tả ngắn gọn về recommendation XXX - Lấy từ tài liệu CIS Nginx Benchmark (bắt buộc dịch sang tiếng Việt)]

## Tổng quan về Detector XXX

### Mục tiêu của Detector XXX

[Mục tiêu của detector XXX (dựa trên Recommendation XXX của CIS Benchmark) - Đầu vào là AST của cấu hình NGINX (JSON) từ thư viện Crossplane - Đầu ra là danh sách các uncompliances (JSON) để chuyển cho module Auto-Remediation]

### Cách hoạt động của Detector XXX dựa trên BaseRecom

[Mô tả ngắn gọn cách hoạt động của Detector XXX dựa trên [BaseRecom](../../core/scannerEng/base_recom.py).]

### Hàm hỗ trợ dùng để test Detector (dùng cho test_detector_XXX.py):

- **`_dir(directive: str, args: list = None, block: list = None) -> dict`**.
- **`_server_block(directives: list) -> dict`**.
- **`_http_block(directives: list) -> dict`**.
- **`_location_block(args: list, directives: list) -> dict`**.
- **`_make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict`**.

## Phân bố test cases:

| **Loại Test Case**                                                   | **Số lượng Test Case** | **Mục đích chính**                             |
| :------------------------------------------------------------------- | :--------------------- | :--------------------------------------------- |
| Kiểm tra Siêu dữ liệu (Metadata Sanity Checks)                       | 3                      | Kiểm tra ID, Tiêu đề & Các thuộc tính bắt buộc |
| Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) | 42                     | Kiểm tra toàn bộ đường ống                     |

**Tổng số :** 3 + 42 = **45 Test Cases**

### 1. Kiểm tra Siêu dữ liệu (Metadata Sanity Checks) - 3 Test Cases

Kiểm tra các thông tin siêu dữ liệu (metadata) của class `DetectorXXX` để đảm bảo định danh và mô tả chính xác theo chuẩn CIS.

- **ID (1 test case):** Kiểm tra ID của detector phải là `"X.X.X"`.
- **Tiêu đề (1 test case):** Đảm bảo tiêu đề phản ánh đúng yêu cầu (`"[Tiêu đề Recommendation X.X.X chuẩn CIS Benchmark]"`).
- **Thuộc tính bắt buộc (1 test case):** Đảm bảo class có đầy đủ các thuộc tính thông tin như `description` (mô tả), `audit_procedure` (quy trình kiểm tra), `impact` (tác động), và `remediation` (biện pháp khắc phục) để hiển thị trên Frontend Dashboard.

### 2. Kiểm thử hàm `scan()`: Toàn bộ đường ống (Full Pipeline Integration) - 42 Test Cases

Đánh giá toàn diện việc bắt lỗi cấu hình (gồm một hoặc nhiều file cấu hình Nginx) dựa vào JSON AST từ `crossplane`.

- **[Chi tiết về các nhóm test cases nhỏ hơn 1]**
- **[Chi tiết về các nhóm test cases nhỏ hơn 2]**
- **[Chi tiết về các nhóm test cases nhỏ hơn 3]**
- **[Chi tiết về các nhóm test cases nhỏ hơn 4]**
- ...
