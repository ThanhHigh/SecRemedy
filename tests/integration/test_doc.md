# SecRemedy test case distribution

## Presets:

| Index | Preset Name               | Description                                                                                                       |
| :---- | :------------------------ | :---------------------------------------------------------------------------------------------------------------- |
| 1     | Nginx-Django-uWSGI        | Nginx configured as a reverse proxy for a Django application using uWSGI with SSL and subfolder redirects.        |
| 2     | Nginx-Frontend-SPA-CDN    | Serves a frontend SPA with SSL and a dedicated CDN server block for optimized static asset delivery.              |
| 3     | Nginx-SPA-PHP-FPM         | Combines a static SPA frontend with a PHP-FPM backend for API routes under SSL.                                   |
| 4     | Nginx-WordPress-PHP-FPM   | Standard WordPress installation using PHP-FPM with SSL and specialized WordPress security/general configs.        |
| 5     | Nginx-Magento-PHP-FPM-CDN | Advanced Magento 2 setup using PHP-FPM, SSL, and a separate CDN server block for high-performance static content. |
| 6     | Nginx-NodeJS-Proxy        | Simple SSL-enabled reverse proxy forwarding traffic to a Node.js application running on local port 3000.          |

---

## Compliance distributions:

| No. compliances | No. test cases | No. presets involved | Preset not involved    | Reason for not involved    |
| :-------------- | -------------- | :------------------- | :--------------------- | -------------------------- |
| 0               | 5              | 5                    | Nginx-Frontend-SPA-CDN | (2) is not a reverse proxy |
| 1               | 12             | 5                    | Nginx-Frontend-SPA-CDN | (2) is not a reverse proxy |
| 2               | 7              | 6                    |                        |                            |
| 3               | 7              | 6                    |                        |                            |
| 4               | 7              | 6                    |                        |                            |
| 5               | 7              | 6                    |                        |                            |
| 6               | 7              | 6                    |                        |                            |
| 7               | 7              | 6                    |                        |                            |
| 8               | 7              | 6                    |                        |                            |
| 9               | 7              | 6                    |                        |                            |
| 10              | 7              | 6                    |                        |                            |
| 11              | 7              | 6                    |                        |                            |
| 12              | 6              | 6                    |                        |                            |
