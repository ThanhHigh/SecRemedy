# Scanner Report - Port 2242

```text
[Scanner] ✅ Scan result saved to: tmp/contracts/scan_result/scan_result_2242.json

[Scanner] 🔍 Chi tiết kết quả kiểm tra (Detailed Findings):
  ❌ 2.4.1 - Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền
  ❌ 2.4.2 - Đảm bảo các yêu cầu đến tên máy chủ không xác định bị từ chối
  ❌ 2.5.1 - Đảm bảo chỉ thị server_tokens được đặt thành 'off'
  ❌ 2.5.2 - Đảm bảo các trang lỗi mặc định và trang index.html không tham chiếu đến NGINX
  ✅ 2.5.3 - Đảm bảo vô hiệu hóa việc phục vụ các file ẩn
  ✅ 2.5.4 - Đảm bảo NGINX reverse proxy không tiết lộ thông tin backend
  ❌ 3.2 - Đảm bảo tính năng ghi log truy cập (access_log) được bật
  ❌ 3.4 - Đảm bảo các proxy chuyển tiếp thông tin IP nguồn
  ✅ 4.1.1 - Đảm bảo HTTP được chuyển hướng sang HTTPS
  ✅ 5.1.1 - Đảm bảo các bộ lọc allow và deny giới hạn truy cập từ các địa chỉ IP cụ thể
  ✅ 5.3.1 - Đảm bảo header X-Content-Type-Options được cấu hình và kích hoạt
  ❌ 5.3.2 - Đảm bảo Content Security Policy (CSP) được bật và cấu hình hợp lý

[Scanner] 📊 Compliance Score: 42%
[Scanner] 📋 Total: 12 | ✅ Pass: 5 | ❌ Fail: 7
```
