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
