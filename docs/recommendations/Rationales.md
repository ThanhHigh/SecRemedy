# 1\. Initial Setup

* **1.1.1 Ensure NGINX is installed (Manual)**  
  * *Rationale:* NGINX must be installed and operational to serve as the target for this benchmark's security controls. Enforcing a minimum version and feature set ensures the platform is capable of supporting the required security configurations.  
* **1.2.1 Ensure package manager repositories are properly configured (Manual)**  
  * *Rationale:* If a system's package manager repositories are misconfigured or outdated, critical security patches may not be applied in a timely manner. Using official repositories ensures access to the latest versions directly from the source.  
* **1.2.2 Ensure the latest software package is installed (Manual)**  
  * *Rationale:* Up-to-date software provides the best possible protection against exploitation of security vulnerabilities, such as the execution of malicious code.

# 2\. Basic Configuration

* **2.1.1 Ensure only required dynamic modules are loaded (Manual)**  
  * *Rationale:* Minimizing the loaded code reduces the potential attack surface. Ensuring that no unnecessary dynamic modules are loaded prevents the execution of unneeded code.  
* **2.2.1 Ensure that NGINX is run using a non-privileged, dedicated service account (Manual)**  
  * *Rationale:* Using a privileged account like root significantly increases the risk of lateral movement if an attacker exploits a vulnerability in a worker process.  
* **2.2.2 Ensure the NGINX service account is locked (Manual)**  
  * *Rationale:* Explicitly locking the NGINX service account prevents password-based logins and blocks adversaries from using the account for lateral movement.  
* **2.2.3 Ensure the NGINX service account has an invalid shell (Manual)**  
  * *Rationale:* The NGINX service account is strictly for running daemon processes. Assigning it a valid login shell unnecessarily expands the attack surface.  
* **2.3.1 Ensure NGINX directories and files are owned by root (Manual)**  
  * *Rationale:* If a non-privileged user can modify configuration files, they can trivially escalate privileges. Only root should own these files to ensure changes require administrative rights.  
* **2.3.2 Ensure access to NGINX directories and files is restricted (Manual)**  
  * *Rationale:* Restrictive file permissions prevent unauthorized users from viewing sensitive configuration details, acting as a fundamental defense against information disclosure.  
* **2.3.3 Ensure the NGINX process ID (PID) file is secured (Manual)**  
  * *Rationale:* Securing the PID file prevents unauthorized modification that could cause a denial of service.  
* **2.4.1 Ensure NGINX only listens for network connections on authorized ports (Manual)**  
  * *Rationale:* Limiting listening ports ensures no unintended services are exposed and enforces strict control over accessible protocols.  
* **2.4.2 Ensure requests for unknown host names are rejected (Manual)**  
  * *Rationale:* Explicitly rejecting unknown host names prevents Host Header attacks and helps distinguish legitimate traffic in logs.  
* **2.4.3 Ensure keepalive\_timeout is 10 seconds or less, but not 0 (Manual)**  
  * *Rationale:* Setting a keep-alive timeout helps mitigate denial of service attacks that exhaust server resources via too many persistent connections.  
* **2.4.4 Ensure send\_timeout is set to 10 seconds or less, but not 0 (Manual)**  
  * *Rationale:* Setting the send\_timeout helps mitigate slow HTTP denial of service attacks by ensuring slow write operations are closed.  
* **2.5.1 Ensure server\_tokens directive is set to off (Manual)**  
  * *Rationale:* Hiding the version slows down reconnaissance and deters attackers targeting specific known vulnerabilities.  
* **2.5.2 Ensure default error and index.html pages do not reference NGINX (Manual)**  
  * *Rationale:* Replacing default pages removes information leakage vectors that attackers use to identify technology stacks.  
* **2.5.3 Ensure hidden file serving is disabled (Manual)**  
  * *Rationale:* Blocking requests to paths starting with a dot prevents the accidental disclosure of sensitive credentials or source code.  
* **2.5.4 Ensure the NGINX reverse proxy does not enable information disclosure (Manual)**  
  * *Rationale:* Removing backend response headers reduces the information available for targeted attacks against the application stack.

# 3\. Logging

* **3.1 Ensure detailed logging is enabled (Manual)**  
  * *Rationale:* Detailed structured logs (JSON) provide a self-describing format for effective incident response and forensic searching.  
* **3.2 Ensure access logging is enabled (Manual)**  
  * *Rationale:* Access logs are primary records of system usage. Disabling them destroys the forensic chain of custody for security events.  
* **3.3 Ensure error logging is enabled and set to the info logging level (Manual)**  
  * *Rationale:* Error logs provide internal context necessary to diagnose failures, process anomalies, and configuration errors.  
* **3.4 Ensure proxies pass source IP information (Manual)**  
  * *Rationale:* Visibility of the true client IP is essential for auditing, incident response, and access control compliance.

# 4\. Encryption

* **4.1.1 Ensure HTTP is redirected to HTTPS (Manual)**  
  * *Rationale:* Redirecting traffic ensures all user communications are encrypted, building trust and maintaining security visibility.  
* **4.1.2 Ensure a trusted certificate and trust chain is installed (Manual)**  
  * *Rationale:* Properly installed certificates prevent browsers from flagging the server as untrusted.  
* **4.1.3 Ensure private key permissions are restricted (Manual)**  
  * *Rationale:* Restricting private key permissions ensures only the server identity can access the key used to decrypt traffic.  
* **4.1.4 Ensure only modern TLS protocols are used (Manual)**  
  * *Rationale:* Disabling legacy protocols (SSL 3.0, TLS 1.0/1.1/1.2) and enabling TLS 1.3 removes insecure cipher suites and supports perfect forward secrecy.  
* **4.1.5 Disable weak ciphers (Manual)**  
  * *Rationale:* Exclusive use of TLS 1.3 is the most effective way to mandate high-security AEAD ciphers and prevent data compromise.  
* **4.1.6 Ensure awareness of TLS 1.3 new Diffie-Hellman parameters (Manual)**  
  * *Rationale:* TLS 1.3 uses standardized secure groups, eliminating risks associated with weak or custom DH parameters.  
* **4.1.7 Ensure Online Certificate Status Protocol (OCSP) stapling is enabled (Manual)**  
  * *Rationale:* OCSP stapling with Must-Staple ensures that certificate revocation is reliably enforced, blocking compromised certificates.  
* **4.1.8 Ensure HTTP Strict Transport Security (HSTS) is enabled (Manual)**  
  * *Rationale:* HSTS prevents protocol downgrade attacks and cookie hijacking by enforcing HTTPS across the domain and subdomains.  
* **4.1.9 Ensure upstream server traffic is authenticated with a client certificate (Manual)**  
  * *Rationale:* mTLS provides cryptographic proof of identity, preventing unauthorized services from accessing sensitive backends.  
* **4.1.10 Ensure the upstream traffic server certificate is trusted (Manual)**  
  * *Rationale:* Validating upstream certificates guarantees NGINX is communicating with authentic backend services, preventing MitM attacks.  
* **4.1.11 Ensure Secure Session Resumption is Enabled (Manual)**  
  * *Rationale:* TLS 1.3 resumption preserves Perfect Forward Secrecy by combining pre-shared keys with fresh ephemeral key exchanges.  
* **4.1.12 Ensure HTTP/3.0 is used (Manual)**  
  * *Rationale:* HTTP/3 offers faster, more reliable connections by mitigating TCP's head-of-line blocking, benefiting modern mobile clients.

# 5\. Request Filtering and Restrictions

* **5.1.1 Ensure allow and deny filters limit access to specific IP addresses (Manual)**  
  * *Rationale:* Applying network-layer least privilege reduces the attack surface by explicitly defining permitted access ranges.  
* **5.1.2 Ensure only approved HTTP methods are allowed (Manual)**  
  * *Rationale:* Disabling unused HTTP methods (like PUT or DELETE) mitigates the risk of unauthorized server interaction.  
* **5.2.1 Ensure timeout values for reading the client header and body are set correctly (Manual)**  
  * *Rationale:* Low timeouts are a primary defense against slow-read DoS attacks that attempt to exhaust server resources.  
* **5.2.2 Ensure the maximum request body size is set correctly (Manual)**  
  * *Rationale:* Limiting request body size prevents resource exhaustion and stops oversized payloads from reaching backends.  
* **5.2.3 Ensure the maximum buffer size for URIs is defined (Manual)**  
  * *Rationale:* Defining buffer sizes prevents memory exhaustion from large headers and protects fragile downstream applications.  
* **5.2.4 Ensure the number of connections per IP address is limited (Manual)**  
  * *Rationale:* Connection limiting prevents single malicious clients from consuming a disproportionate share of worker resources.  
* **5.2.5 Ensure rate limits by IP address are set (Manual)**  
  * *Rationale:* Rate limiting targets high-frequency attacks like brute-force guessing and automated API abuse.  
* **5.3.1 Ensure X-Content-Type-Options header is configured and enabled (Manual)**  
  * *Rationale:* The 'nosniff' directive prevents drive-by downloads and MIME type confusion attacks in user agents.  
* **5.3.2 Ensure that Content Security Policy (CSP) is enabled and configured properly (Manual)**  
  * *Rationale:* A robust CSP neutralizes XSS vectors and controls page embedding to protect against Clickjacking.  
* **5.3.3 Ensure the Referrer Policy is enabled and configured properly (Manual)**  
  * *Rationale:* Configuring Referrer Policy protects user privacy by preventing the leakage of sensitive URL data to third parties.

