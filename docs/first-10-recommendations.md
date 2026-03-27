### 2.4.1 Ensure NGINX only listens for network connections on authorized ports (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

NGINX should be configured to listen only on authorized ports and protocols. While traditional HTTP/1.1 and HTTP/2 use TCP ports 80 and 443, modern HTTP/3 (QUIC) utilizes UDP port 443. Ensuring that NGINX binds only to approved interfaces and ports minimizes the attack surface.

## Rationale:

Limiting listening ports to authorized values ensures that no hidden or unintended services are exposed via NGINX. It also enforces strict control over which protocols (TCP vs. UDP) are accessible, which is particularly important with the introduction of UDP-based HTTP/3 traffic alongside traditional TCP traffic.

## Impact

Disabling unused ports reduces the risk of unauthorized access. However, administrators must be aware that disabling UDP port 443 will break HTTP/3 connectivity, forcing clients to fall back to slower TCP-based HTTP/2 or HTTP/1.1.

## Audit

Run the command `nginx -T 2>/dev/null | grep -r "listen"` to inspect all listen directives in the loaded configuration. Review the output for unauthorized ports, ensuring no other ports (e.g., 8080, 8443) are open unless explicitly authorized. Optionally, verify what the process is actually binding to on the OS level using the command `netstat -tulpen | grep -i nginx`.

## Remediation

Remove or comment out any listen directives that bind to unauthorized ports. For HTTP/3 (QUIC) support, ensure that you explicitly authorize and configure UDP port 443 in addition to TCP port 443.

## Default Value

By default, NGINX often listens only on TCP port 80. Modern secure defaults should listen on TCP 80 (for redirect), TCP 443, and optionally UDP 443 (for HTTP/3).

---

### 2.4.2 Ensure requests for unknown host names are rejected (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

NGINX routes incoming requests to the appropriate virtual host by matching the Host header or :authority pseudo-header against the server_name directives in your configuration. If no explicit match is found, NGINX falls back to the first defined server block or the one marked as default_server. Without a properly configured catch-all block that rejects unknown hostnames, your server will respond to arbitrary domain names that happen to point to your IP address, potentially exposing internal applications or enabling Host Header attacks.

## Rationale:

When NGINX receives a request, it selects the virtual host based on the Host header. If requests for unknown host names are not explicitly rejected, your applications may be served for arbitrary domains that simply point to your IP. This behavior can be abused in Host Header attacks and makes it harder to distinguish legitimate traffic from automated scans or misrouted requests in your logs.

## Impact

Clients accessing the server directly via IP address or an unconfigured CNAME will be rejected. This is intended behavior but requires that all valid domains are explicitly defined in their own server blocks.

## Audit

Check for the existence of a default server block that handles unknown hosts using `nginx -T 2>/dev/null | grep -Ei "listen.*default_server|ssl_reject_handshake"`. Ensure a server block exists with `listen ... default_server` and verify it contains `return 444;` or a 4xx error code. For HTTPS/TLS, verify `ssl_reject_handshake on;` is used to prevent certificate leakage. Finally, send a request with an invalid Host header and verify the connection is rejected or returns an error.

## Remediation

Configure a "Catch-All" default server block as the first block in your configuration (or explicitly marked with default_server). After adding this block, ensure all your valid applications have their own server blocks with explicit server_name directives.

## Default Value

By default, if no default_server is defined, NGINX uses the first server block configuration it finds, potentially serving your application for any incoming request regardless of the Host header.

---

### 2.5.1 Ensure server_tokens directive is set to `off` (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

The server_tokens directive is responsible for displaying the NGINX version number and operating system version on error pages and in the Server HTTP response header field. This information should not be displayed.

## Rationale:

Attackers can conduct reconnaissance on a website using these response headers, then target attacks for specific known vulnerabilities associated with the underlying technologies. Hiding the version will slow down and deter some potential attackers.

## Impact

None. Disabling server tokens does not affect functionality, as it merely removes the version string from error pages and headers. Note that determined attackers can still fingerprint NGINX via other methods, but removing the banner raises the bar for opportunistic scanners.

## Audit

In the NGINX configuration file `nginx.conf`, verify the server_tokens directive is set to off. To do this, check the response headers for the server header by issuing the command `curl -I 127.0.0.1 | grep -i server`. The output should not contain the server header providing your server version.

## Remediation

Disable version disclosure globally by adding the directive `server_tokens off;` to the http block in `/etc/nginx/nginx.conf`.

## Default Value

The default value of server_tokens is on.

---

### 2.5.2 Ensure default error and index.html pages do not reference NGINX (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

Default error pages (e.g., 404, 500) and the default welcome page often contain NGINX branding or signatures. These pages should be removed or replaced with generic or custom-branded pages that do not disclose the underlying server technology.

## Rationale:

Standard NGINX error pages visually identify the server software, even if headers are suppressed. By gathering information about the underlying technology stack, attackers can tailor their exploits to known vulnerabilities of NGINX. Replacing default pages with generic or branded content removes this information leakage vector and increases the effort required for successful reconnaissance.

## Impact

Creating and maintaining custom error pages requires additional administrative effort. Ensure that custom error pages are simple and do not themselves introduce vulnerabilities.

## Audit

Check if error_page directives are active by running `nginx -T 2>/dev/null | grep -i "error_page"`. Trigger an error (e.g., request a non-existent page) and inspect the body to verify the output does not contain "nginx".

## Remediation

Instead of editing the default files, configure NGINX to use custom error pages. Create a directory and place generic HTML files there without NGINX branding, and add the error_page directive to your http or server blocks.

## Default Value

Default error pages identify the server as NGINX.

---

### 2.5.3 Ensure hidden file serving is disabled (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

Hidden files and directories (starting with a dot, e.g., .git, .env) often contain sensitive metadata, version control history, or environment configurations. Serving these files should be globally disabled.

## Rationale:

Version control systems and editors create hidden files that may unintentionally be deployed to the web root. If accessible, files like .git/config or .env can leak database credentials, source code, and infrastructure details, leading to full system compromise. Blocking requests to any path starting with a dot neutralizes this risk.

## Impact

Blocking all dot-files will break Let's Encrypt / Certbot validation (.well-known/acme-challenge) unless explicitly allowed. Ensure the exception rule is placed before the deny rule or is more specific.

## Audit

Search the loaded configuration for hidden file protection rules using `nginx -T 2>/dev/null | grep "location.*\\\."` and look for a block like `location ~ /\. { deny all; ... }`. Optionally, try to access a dummy hidden file and verify it returns a 403 Forbidden or 404 Not Found.

## Remediation

To restrict access to hidden files, add a configuration block denying access to hidden files inside each server block directly, or create a reusable snippet file containing the rules and include it in your server blocks.

## Default Value

This protection is not set by default. NGINX will serve any hidden file if it exists in the web root.

---

### 3.1 Ensure detailed logging is enabled (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

System logging must be configured to meet organizational security and privacy policies. Detailed logs provide the necessary context for incident response and forensic analysis, with modern strategies favoring structured formats (JSON).

## Rationale:

Detailed logs are the foundation of effective incident response. Traditional text logs require complex parsing, whereas structured logging (JSON) provides a self-describing format natively ingested by modern analysis tools.

## Impact

Enabling detailed JSON logging increases the volume of log data. Ensure that log rotation policies and disk space monitoring are adjusted to handle the increased storage requirements.

## Audit

Inspect the log_format directives to confirm a detailed format is defined and includes critical fields. Check that the defined format is actually used by the access_log directive.

## Remediation

Define a detailed log format in the http block of `/etc/nginx/nginx.conf`, preferably using JSON format for compatibility with modern SIEM tools, and apply it globally or per server.

## Default Value

By default, NGINX uses the combined log format, which is a standard text format but lacks details.

---

### 3.2 Ensure access logging is enabled (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

The access_log directive enables the logging of client requests. While enabled by default, NGINX allows granular control per server or location context.

## Rationale:

Access logs are the primary record of system usage, detailing who accessed what resources. Without active access logs, incident responders are blind to web-based attacks and auditors cannot verify compliance or user activity.

## Impact

Enabling detailed access logging increases disk space usage significantly. Without proper log rotation and monitoring, log files can rapidly consume available disk space, potentially causing the server to crash.

## Audit

Inspect the fully loaded configuration for log settings and verify that access_log directives point to a valid local file path. Identify any instances of `access_log off;` and ensure it is not applied globally.

## Remediation

Enable access logging in the http block to set a secure global default, or configure it explicitly within specific server blocks.

## Default Value

Access logging is enabled by default, typically logging to logs/access.log or /var/log/nginx/access.log using the standard combined format.

---

### 3.3 Ensure error logging is enabled and set to the info logging level (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

The error_log directive configures logging for server errors and operational messages. The log level determines the verbosity of these messages and should be set to capture sufficient detail (typically notice or info).

## Rationale:

Error logs provide the internal system context required to diagnose why a request failed. They are essential for identifying upstream failures, process anomalies, and configuration errors.

## Impact

Setting the log level to info can generate a significant volume of log data, increasing disk I/O and storage requirements. Ensure that log rotation is configured and storage usage is monitored.

## Audit

Check the fully loaded configuration for error log settings and verify that error_log is defined globally in the main context. Confirm it points to a valid local file and the level is set according to internal policy.

## Remediation

Configure the error_log directive in the main context to capture operational events, setting the specific logging level to align with organizational policy (typically info or notice).

## Default Value

By default, NGINX logs errors to logs/error.log with the severity level error.

---

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

### 4.1.1 Ensure HTTP is redirected to HTTPS (Manual)

## Profile Applicability:

Level 1 - Webserver, Level 1 - Proxy, Level 1 - Loadbalancer.

## Description:

Browsers and clients establish encrypted connections with servers by leveraging HTTPS. Unencrypted requests should be redirected so they are encrypted, meaning any listening HTTP port on your web server should redirect to a server profile that uses encryption.

## Rationale:

Redirecting user agent traffic to HTTPS helps to ensure all user traffic is encrypted. Modern browsers alert users that your website is insecure when HTTPS is not used, which can decrease user trust.

## Impact

Use of HTTPS does result in a performance reduction in traffic to your website, however, many businesses consider this to be a cost of doing business.

## Audit

To verify your server listening configuration, check your web server or proxy configuration file. The configuration file should return a statement redirecting to HTTPS.

## Remediation

Edit your web server or proxy configuration file to redirect all unencrypted listening ports using a redirection through the return directive.

## Default Value

NGINX is not configured to use HTTPS or redirect to it by default.
