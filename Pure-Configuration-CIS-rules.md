# 🛡️ 10 Luật CIS Benchmark Hoàn Hảo Cho MVP của SecRemedy

## Nhóm 1: Chống lộ lọt thông tin & Tấn công dò quét (Information Disclosure)

1. **2.5.1 Ensure server_tokens directive is set to off**
   1. _Mục đích:_ Ẩn phiên bản Nginx khỏi HTTP Response Header.
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Chèn hoặc sửa thành server_tokens off;.
2. **2.5.3 Ensure hidden file serving is disabled**
   1. _Mục đích:_ Chặn truy cập các file ẩn (như .git, .env) chứa dữ liệu nhạy cảm.
   2. _Nginx Context:_ server.
   3. _Auto-Remediation:_ Inject nguyên một block: location \~ /\\. { deny all; return 404; }

## Nhóm 2: Tối ưu hóa Timeout chống Denial of Service (DoS)

3. **2.4.3 Ensure keepalive_timeout is 10 seconds or less, but not 0**
   1. _Mục đích:_ Ngăn chặn các kết nối dai dẳng làm cạn kiệt tài nguyên (Slow-read DoS).
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Cập nhật/Chèn keepalive_timeout 10;.
4. **2.4.4 Ensure send_timeout is set to 10 seconds or less, but not 0**
   1. _Mục đích:_ Đóng các kết nối ghi chậm chạp.
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Cập nhật/Chèn send_timeout 10;.
5. **5.2.1 Ensure timeout values for reading the client header and body are set correctly**
   1. _Mục đích:_ Chặn Slowloris attacks.
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Cập nhật/Chèn client_header_timeout 15s; và client_body_timeout 15s;.
6. **5.2.2 Ensure the maximum request body size is set correctly**
   1. _Mục đích:_ Ngăn chặn payload quá khổ làm tràn RAM server.
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Cập nhật/Chèn client_max_body_size 2M;.

## Nhóm 3: Tiêu chuẩn Mã hóa (Encryption & TLS)

7. **4.1.4 Ensure only modern TLS protocols are used**
   1. _Mục đích:_ Loại bỏ các giao thức cũ bị lỗi (như TLSv1.2, TLSv1.1) để chống downgrade attacks.
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Sửa thành ssl_protocols TLSv1.3;.

## Nhóm 4: HTTP Security Headers (Browser Security)

8. **4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled**
   1. _Mục đích:_ Ép trình duyệt luôn dùng HTTPS.
   2. _Nginx Context:_ server.
   3. _Auto-Remediation:_ Chèn add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;.
9. **5.3.1 Ensure X-Content-Type-Options header is configured and enabled**
   1. _Mục đích:_ Chống MIME type sniffing.
   2. _Nginx Context:_ http, server.
   3. _Auto-Remediation:_ Chèn add_header X-Content-Type-Options "nosniff" always;.
10. **5.3.3 Ensure the Referrer Policy is enabled and configured properly**
    1. _Mục đích:_ Bảo vệ quyền riêng tư, tránh rò rỉ session token qua URL sang site bên thứ 3\.
    2. _Nginx Context:_ http, server.
    3. _Auto-Remediation:_ Chèn add_header Referrer-Policy "strict-origin-when-cross-origin" always;.
