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
