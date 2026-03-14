# Sử dụng Nginx bản mới nhất trên nền Debian
FROM nginx:1.28

# Cài đặt OpenSSH Server và OpenSSL
RUN apt-get update && apt-get install -y openssh-server openssl && rm -rf /var/lib/apt/lists/*

# Cấu hình SSH: Tạo thư mục run, đổi mật khẩu root thành 'root', cho phép root login
RUN mkdir -p /var/run/sshd
RUN echo 'root:root' | chpasswd
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Tự động sinh chứng chỉ SSL giả lập để test luật TLS và HSTS
RUN mkdir -p /etc/ssl/mock_certs && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/mock_certs/nginx.key \
    -out /etc/ssl/mock_certs/nginx.crt \
    -subj "/C=VN/ST=HN/L=HN/O=DevSecOps/CN=localhost" && \
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/ssl/mock_certs/admin.key \
    -out /etc/ssl/mock_certs/admin.crt \
    -subj "/C=VN/ST=HN/L=HN/O=DevSecOps/CN=admin"

# Mở port 80 (HTTP), 443 (HTTPS) và 22 (SSH)
EXPOSE 80 443 22

# Khởi chạy cả SSHD và Nginx khi container start
CMD ["/bin/sh", "-c", "/usr/sbin/sshd && nginx -g 'daemon off;'"]