
# 🛡️ Nginx Security Assessment & Remediation Rules (CIS Based)

Tài liệu này định nghĩa **5 quy tắc bảo mật trọng tâm** dựa trên tiêu chuẩn **CIS Nginx Benchmark v3.0.0**.

---

## 1. Disable Server Tokens (Information Leakage)

**CIS ID:** 2.1.3 | **Block:** `http`, `server`, `location`

Ẩn phiên bản Nginx để ngăn khai thác CVE.

```nginx
server_tokens off;
```

---

## 2. HTTP Strict Transport Security - HSTS

**CIS ID:** 5.1.2 | **Block:** `server` (HTTPS only)

Ép buộc giao tiếp HTTPS, chống Protocol Downgrade.

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

---

## 3. Clickjacking Protection (X-Frame-Options)

**CIS ID:** 5.1.3 | **Block:** `http`, `server`

Ngăn nhúng trang web vào iframe độc hại.

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
```

---

## 4. MIME Sniffing Prevention (X-Content-Type-Options)

**CIS ID:** 5.1.4 | **Block:** `http`, `server`

Ngăn trình duyệt tự động thực thi file sai định dạng.

```nginx
add_header X-Content-Type-Options "nosniff" always;
```

---

## 5. Modern TLS Protocols Only

**CIS ID:** 4.1.1 | **Block:** `http`, `server`, `location`

Chỉ cho phép TLS 1.2 và TLS 1.3.

**Inbound (Client → Nginx):**
```nginx
server {
    ssl_protocols TLSv1.2 TLSv1.3;
}
```

**Outbound (Nginx → Upstream):**
```nginx
location / {
    proxy_pass https://upstream;
    proxy_ssl_protocols TLSv1.2 TLSv1.3;
}
```
