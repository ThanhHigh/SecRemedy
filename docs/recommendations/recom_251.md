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
