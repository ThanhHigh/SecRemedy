Phần này sẽ hoàn thiện hệ thống, triển khai Backend (các API) và Frontend.
Backend sử dụng FastAPI
Frontend sử dụng ReactJS

Backend sẽ cần sẽ tương tác với phần core
Các API cần thiết
- Upload file/folder cấu hình
- Download file cấu hình về server từ một IP khác (biết port) dùng SSH thông qua fetcher trong core
- Quá trình quét phân tích Scanner - các API cần thiết: đọc và quét
- Quá trình sửa lỗi Remedy - các API cần thiết: tương tác vs người dùng trong quá trình sửa, hiển thị diff code, form để phê duyệt, download file cấu hình đã sửa

Frontend sẽ cần xây dựng giao diện người dùng để tương tác với các API trên, bao gồm:
- Trang chủ với form upload file/folder cấu hình
- Trang hiển thị kết quả quét phân tích, bao gồm danh sách lỗi, các điều luật đã thỏa mãn
- Trang hiển thị quá trình sửa lỗi, bao gồm diff code và form phê duyệt
- Trang quản lý cấu hình đã sửa, cho phép tải về file cấu hình đã an toàn


