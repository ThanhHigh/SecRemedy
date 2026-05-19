FROM nginx:1.28

# Install deps
RUN apt-get update && apt-get install -y \
    openssh-server \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# SSH setup
RUN mkdir -p /var/run/sshd \
    && ssh-keygen -A \
    && echo 'root:root' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config

# Pre-generate TLS assets (required by configs referencing dhparam/ssl certs)
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
       -keyout /etc/ssl/private/nginx.key \
       -out    /etc/ssl/certs/nginx.crt \
       -subj   "/CN=localhost" \
    && openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

# Ensure modules-enabled dir exists (nginx.conf includes it)
RUN mkdir -p /etc/nginx/modules-enabled \
    && mkdir -p /etc/nginx/conf.d \
    && mkdir -p /etc/nginx/sites-available \
    && mkdir -p /etc/nginx/sites-enabled

EXPOSE 80 443 22

# Start sshd + nginx (daemon off)
# Note: we copy dhparam.pem if it doesn't exist in the mounted /etc/nginx
CMD ["/bin/sh", "-c", "cp -n /etc/ssl/certs/dhparam.pem /etc/nginx/dhparam.pem 2>/dev/null || true; /usr/sbin/sshd && nginx -g 'daemon off;'"]
