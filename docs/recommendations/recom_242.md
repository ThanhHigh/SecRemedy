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
