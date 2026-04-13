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

---
