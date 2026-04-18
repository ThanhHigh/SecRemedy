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
