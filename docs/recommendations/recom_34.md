### 3.4 Ensure proxies pass source IP information (Manual)

## Profile Applicability:

Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

When NGINX acts as a reverse proxy or load balancer, it terminates the client connection and opens a new connection to the upstream application server. Standard HTTP headers like X-Forwarded-For and X-Real-IP must be explicitly configured to pass the original client's IP address.

## Rationale:

Visibility of the true client IP address is essential for security auditing, incident response, and access control within the backend application. Without forwarding this information, application logs will show all traffic coming from the NGINX proxy IP.

## Impact

Enabling these headers allows the backend application to see the original client IP. However, if NGINX simply appends to an existing X-Forwarded-For header sent by a malicious client, the backend might be tricked into trusting a spoofed IP.

## Audit

Check the active configuration for proxy header directives in proxied locations and verify that `proxy_set_header X-Forwarded-For` and `proxy_set_header X-Real-IP` are present.

## Remediation

Configure NGINX to forward client IP information in your server or location blocks where proxy_pass is used.

## Default Value

By default, NGINX does not add these headers. The upstream server receives requests appearing to originate from the NGINX server's IP address.

---
