from enum import Enum
from dataclasses import dataclass
from typing import List, Dict, Optional


class RecomID(str, Enum):
    """
    Unique identifier for each CIS Recommendation.
    Using Enum (str) for fast O(1) dictionary retrieval and IDE autocompletion.
    """
    CIS_2_4_1 = "2.4.1"
    CIS_2_4_2 = "2.4.2"
    CIS_2_5_1 = "2.5.1"
    CIS_2_5_2 = "2.5.2"
    CIS_2_5_3 = "2.5.3"
    CIS_2_5_4 = "2.5.4"
    CIS_3_2 = "3.2"
    CIS_3_4 = "3.4"
    CIS_4_1_1 = "4.1.1"
    CIS_5_1_1 = "5.1.1"
    CIS_5_3_1 = "5.3.1"
    CIS_5_3_2 = "5.3.2"


@dataclass(frozen=True)
class Recommendation:
    """
    In-memory data structure for storing recommendation metadata.
    'frozen=True' ensures data integrity at run-time.
    """
    id: RecomID
    title: str
    description: str
    audit_procedure: str
    impact: str
    remediation_procedure: str


# Fast-to-retrieve In-Memory Registry (RAM)
# Both Scanner Engine (Detectors) and Remediation Engine (Injectors) can import this.
RECOMMENDATION_REGISTRY: Dict[RecomID, Recommendation] = {
    RecomID.CIS_2_4_1: Recommendation(
        id=RecomID.CIS_2_4_1,
        title="Đảm bảo NGINX chỉ lắng nghe kết nối mạng trên các cổng được ủy quyền",
        description="NGINX chỉ nên được cấu hình để lắng nghe trên các cổng và giao thức được ủy quyền. Việc này giúp giảm thiểu bề mặt tấn công và kiểm soát chặt chẽ các giao thức có thể truy cập.",
        audit_procedure="1. Chạy 'nginx -T 2>/dev/null | grep -r \"listen\"' để kiểm tra file cấu hình. 2. Chạy 'netstat -tulpen | grep -i nginx' để kiểm tra OS. Đảm bảo không có cổng lạ mở.",
        impact="Giảm rủi ro truy cập trái phép. Lưu ý: vô hiệu hóa UDP 443 sẽ làm hỏng HTTP/3, buộc client lùi về HTTP/2 hoặc HTTP/1.1 (TCP).",
        remediation_procedure="Xóa hoặc comment các lệnh listen liên kết với cổng không được ủy quyền. Với HTTP/3, cấu hình thêm 'listen 443 quic reuseport;' bên cạnh TCP 443."
    ),
    RecomID.CIS_2_4_2: Recommendation(
        id=RecomID.CIS_2_4_2,
        title="Đảm bảo các yêu cầu đến tên máy chủ không xác định bị từ chối",
        description="NGINX định tuyến yêu cầu dựa trên Host header. Nếu không có block server mặc định (catch-all) để từ chối các host không xác định, máy chủ sẽ phản hồi cho các tên miền bất kỳ trỏ tới IP của bạn, dẫn đến nguy cơ rò rỉ ứng dụng nội bộ hoặc tấn công Host Header.",
        audit_procedure="1. Chạy lệnh 'nginx -T 2>/dev/null | grep -Ei \"listen.*default_server|ssl_reject_handshake\"'. 2. Đảm bảo có block server chứa 'listen ... default_server', có 'return 444;' hoặc mã lỗi 4xx. 3. Với HTTPS, kiểm tra 'ssl_reject_handshake on;'.",
        impact="Các client truy cập trực tiếp bằng địa chỉ IP hoặc qua CNAME chưa cấu hình sẽ bị từ chối. Cần đảm bảo tất cả tên miền hợp lệ đều được định nghĩa rõ trong các block server riêng.",
        remediation_procedure="Cấu hình block server mặc định (Catch-All) chứa 'listen ... default_server;', 'server_name _;' và 'return 444;'. Với HTTPS, thêm 'ssl_reject_handshake on;' để ngăn rò rỉ chứng chỉ TLS."
    ),
    RecomID.CIS_2_5_1: Recommendation(
        id=RecomID.CIS_2_5_1,
        title="Đảm bảo chỉ thị server_tokens được đặt thành 'off'",
        description="Chỉ thị server_tokens hiển thị số phiên bản NGINX và hệ điều hành trên trang lỗi và HTTP header. Việc hiển thị thông tin này giúp kẻ tấn công dễ dàng dò quét và nhắm mục tiêu vào các lỗ hổng đã biết.",
        audit_procedure="1. Chạy lệnh 'curl -I 127.0.0.1 | grep -i server'. 2. Đảm bảo kết quả trả về không chứa thông tin phiên bản cụ thể (ví dụ: không có 'Server: nginx/1.28.0').",
        impact="Không ảnh hưởng chức năng. Ẩn thông tin phiên bản làm chậm kẻ tấn công và hạn chế các rủi ro từ việc quét lỗ hổng tự động.",
        remediation_procedure="Thêm hoặc đổi thành 'server_tokens off;' trong block 'http {}' của file cấu hình NGINX (thường là /etc/nginx/nginx.conf)."
    ),
    RecomID.CIS_2_5_2: Recommendation(
        id=RecomID.CIS_2_5_2,
        title="Đảm bảo các trang lỗi mặc định và trang index.html không tham chiếu đến NGINX",
        description="Các trang lỗi (VD: 404, 500) và trang chào mừng mặc định thường chứa dấu hiệu của NGINX. Cần thay thế bằng các trang tùy chỉnh để không tiết lộ phần mềm máy chủ, giúp ngăn kẻ tấn công nhận dạng công nghệ.",
        audit_procedure="1. Chạy 'nginx -T 2>/dev/null | grep -i \"error_page\"'. 2. Gửi request gây lỗi: 'curl -k https://127.0.0.1/non-existent-page | grep -i \"nginx\"'. Đảm bảo kết quả không trả về từ 'nginx'.",
        impact="Cần thêm thời gian quản trị để tạo và bảo trì trang lỗi. Đảm bảo các trang này đơn giản và không tạo ra lỗ hổng mới.",
        remediation_procedure="Tạo các file HTML tùy chỉnh (VD: 404.html) không chứa thông tin NGINX. Cấu hình NGINX dùng 'error_page 404 /404.html;' và 'location = /404.html { internal; }'."
    ),
    RecomID.CIS_2_5_3: Recommendation(
        id=RecomID.CIS_2_5_3,
        title="Đảm bảo vô hiệu hóa việc phục vụ các file ẩn",
        description="Các file và thư mục ẩn (bắt đầu bằng dấu chấm, VD: .git, .env) thường chứa thông tin nhạy cảm, mã nguồn hoặc cấu hình môi trường. Việc phục vụ các file này cần được vô hiệu hóa để tránh rò rỉ dữ liệu.",
        audit_procedure="1. Chạy lệnh 'nginx -T 2>/dev/null | grep \"location.*\\\\.\"'. 2. Kiểm tra: 'curl -k -I https://127.0.0.1/.git/HEAD'. Đảm bảo trả về 403 hoặc 404.",
        impact="Chặn tất cả file ẩn sẽ làm hỏng xác thực Let's Encrypt/Certbot. Đảm bảo quy tắc ngoại lệ cho '.well-known/acme-challenge' được đặt trước quy tắc từ chối.",
        remediation_procedure="Thêm 'location ~ /\\. { deny all; return 404; }' vào các block server. Thêm 'location ^~ /.well-known/acme-challenge/ { allow all; }' lên trước để không chặn Let's Encrypt."
    ),
    RecomID.CIS_2_5_4: Recommendation(
        id=RecomID.CIS_2_5_4,
        title="Đảm bảo NGINX reverse proxy không tiết lộ thông tin backend",
        description="Khi NGINX đóng vai trò reverse proxy, nó có thể chuyển tiếp các header từ ứng dụng backend (VD: X-Powered-By, Server). Cần loại bỏ các header này trước khi phản hồi cho client để tránh rò rỉ thông tin về công nghệ và phiên bản backend.",
        audit_procedure="1. Chạy 'nginx -T 2>/dev/null | grep -Ei \"(proxy|fastcgi)_hide_header\"'. 2. Chạy 'curl -k -I https://127.0.0.1 | grep -Ei \"^(Server|X-Powered-By)\"'. Đảm bảo kết quả không hiển thị chi tiết về backend.",
        impact="Hạn chế cung cấp thông tin do thám cho kẻ tấn công. Không ảnh hưởng đến chức năng ứng dụng.",
        remediation_procedure="Thêm 'proxy_hide_header X-Powered-By;' và 'proxy_hide_header Server;' nếu dùng proxy_pass. Dùng 'fastcgi_hide_header X-Powered-By;' nếu dùng fastcgi_pass."
    ),
    RecomID.CIS_3_2: Recommendation(
        id=RecomID.CIS_3_2,
        title="Đảm bảo tính năng ghi log truy cập (access_log) được bật",
        description="Chỉ thị access_log cho phép ghi nhận các yêu cầu từ client, cung cấp lịch sử sử dụng hệ thống chi tiết phục vụ điều tra sự cố và kiểm toán. Nếu tắt (access_log off;), hệ thống sẽ mù trước các cuộc tấn công web như SQL injection hay Brute Force.",
        audit_procedure="1. Chạy 'nginx -T 2>/dev/null | grep -i \"access_log\"'. 2. Kiểm tra log được trỏ tới file hợp lệ (VD: /var/log/nginx/). 3. Đảm bảo 'access_log off;' không bị áp dụng toàn cục (http) hoặc ở các block server chứa logic nghiệp vụ quan trọng.",
        impact="Ghi log chi tiết sẽ tốn dung lượng ổ đĩa. Cần cấu hình xoay vòng log (logrotate) và giám sát dung lượng để tránh tình trạng đầy ổ đĩa dẫn đến sập máy chủ.",
        remediation_procedure="Khai báo đường dẫn file log hợp lệ bằng chỉ thị 'access_log' trong block 'http' hoặc 'server'. Xóa bỏ lệnh 'access_log off;' ở các vị trí không phù hợp, chỉ giữ lại ở các đường dẫn ít quan trọng như favicon.ico."
    ),
    RecomID.CIS_3_4: Recommendation(
        id=RecomID.CIS_3_4,
        title="Đảm bảo các proxy chuyển tiếp thông tin IP nguồn",
        description="Khi NGINX hoạt động như một reverse proxy hoặc load balancer, mặc định máy chủ upstream chỉ thấy địa chỉ IP nội bộ của NGINX. Cần cấu hình các HTTP header như X-Forwarded-For và X-Real-IP để chuyển tiếp địa chỉ IP thực của client đến ứng dụng backend.",
        audit_procedure="1. Chạy lệnh 'nginx -T 2>/dev/null | grep -E \"proxy_set_header (X-Real-IP|X-Forwarded-For)\"'. 2. Đảm bảo các cấu hình này có mặt trong các block chứa lệnh chuyển tiếp như proxy_pass.",
        impact="Cho phép ứng dụng backend ghi log và kiểm soát truy cập dựa trên IP thực của client. Cần cấu hình backend tin tưởng đúng IP của proxy NGINX để tránh bị giả mạo header từ phía client.",
        remediation_procedure="Thêm các chỉ thị 'proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;', 'proxy_set_header X-Real-IP $remote_addr;' và 'proxy_set_header X-Forwarded-Proto $scheme;' vào các block cấu hình có sử dụng proxy_pass (hoặc fastcgi_pass)."
    ),
    RecomID.CIS_4_1_1: Recommendation(
        id=RecomID.CIS_4_1_1,
        title="Đảm bảo HTTP được chuyển hướng sang HTTPS",
        description="Các yêu cầu HTTP không được mã hóa. Cần chuyển hướng tất cả lưu lượng truy cập từ cổng HTTP (mặc định là 80) sang HTTPS để đảm bảo toàn bộ dữ liệu người dùng được mã hóa và an toàn.",
        audit_procedure="1. Kiểm tra cấu hình NGINX tại block 'server' lắng nghe cổng 80. 2. Đảm bảo tồn tại chỉ thị chuyển hướng như 'return 301 https://$host$request_uri;'.",
        impact="Có thể gây giảm nhẹ hiệu suất do quá trình bắt tay TLS/SSL, nhưng là chi phí cần thiết để đảm bảo bảo mật và độ tin cậy của dịch vụ.",
        remediation_procedure="Cấu hình block 'server' lắng nghe trên cổng 80 và dùng lệnh 'return 301 https://$host$request_uri;' để chuyển hướng toàn bộ traffic sang HTTPS."
    ),
    RecomID.CIS_5_1_1: Recommendation(
        id=RecomID.CIS_5_1_1,
        title="Đảm bảo các bộ lọc allow và deny giới hạn truy cập từ các địa chỉ IP cụ thể",
        description="Kiểm soát truy cập dựa trên địa chỉ IP là cơ chế bảo mật chuyên sâu cơ bản. Bằng cách sử dụng các chỉ thị allow và deny, quyền truy cập vào các block server hoặc location cụ thể có thể được giới hạn ở các mạng đáng tin cậy, đặc biệt hiệu quả để bảo vệ giao diện quản trị nội bộ.",
        audit_procedure="1. Chạy lệnh 'nginx -T 2>/dev/null | grep -E \"^\\s*(allow|deny)\"'. 2. Kiểm tra thủ công các quy tắc để đảm bảo IP hợp lệ và có 'deny all;'.",
        impact="Cấu hình sai có thể chặn người dùng hợp lệ. Môi trường động thay đổi IP thường xuyên cần quản lý danh sách truy cập cẩn thận.",
        remediation_procedure="Xác định block location cần bảo vệ. Thêm chỉ thị 'allow <IP_hoặc_CIDR>;' cho các nguồn tin cậy, theo sau là 'deny all;' để chặn phần còn lại."
    ),
    RecomID.CIS_5_3_1: Recommendation(
        id=RecomID.CIS_5_3_1,
        title="Đảm bảo header X-Content-Type-Options được cấu hình và kích hoạt",
        description="Header X-Content-Type-Options chỉ thị cho trình duyệt không tự đoán (sniff) kiểu MIME của file, giúp ngăn chặn các cuộc tấn công nhầm lẫn kiểu MIME (MIME type confusion).",
        audit_procedure="1. Chạy lệnh 'nginx -T 2>/dev/null | grep -i \"X-Content-Type-Options\"'. 2. Đảm bảo cấu hình có chứa dòng 'add_header X-Content-Type-Options \"nosniff\" always;'.",
        impact="Có thể làm hỏng các ứng dụng cũ nếu khai báo sai Content-Type (ví dụ: trả về script dưới dạng text/plain).",
        remediation_procedure="Thêm dòng 'add_header X-Content-Type-Options \"nosniff\" always;' vào block server."
    ),
    RecomID.CIS_5_3_2: Recommendation(
        id=RecomID.CIS_5_3_2,
        title="Đảm bảo Content Security Policy (CSP) được bật và cấu hình hợp lý (Thủ công)",
        description="Content Security Policy (CSP) là HTTP header cho phép định nghĩa nguồn tài nguyên được duyệt. Giúp ngăn chặn tấn công XSS và tiêm dữ liệu. Chỉ thị frame-ancestors giúp chống Clickjacking.",
        audit_procedure="1. Chạy lệnh 'nginx -T 2>/dev/null | grep -i \"Content-Security-Policy\"'. 2. Kiểm tra xem header có chứa 'default-src' và 'frame-ancestors' không. Tránh dùng 'unsafe-inline' hoặc 'unsafe-eval'.",
        impact="Cấu hình CSP sai sẽ chặn tài nguyên hợp lệ và làm hỏng ứng dụng. Nên dùng chế độ Content-Security-Policy-Report-Only trước khi áp dụng thật.",
        remediation_procedure="Thêm 'add_header Content-Security-Policy \"default-src 'self'; frame-ancestors 'self'; form-action 'self';\" always;' vào cấu hình NGINX. Cần điều chỉnh theo từng ứng dụng cụ thể."
    ),
}
