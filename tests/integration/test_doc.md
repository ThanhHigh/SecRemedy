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

| No. compliances | No. test cases | No. presets involved | Preset not involved    | Reason for not involved    | Progress | Test case Ids      |
| :-------------- | -------------- | :------------------- | :--------------------- | -------------------------- | -------- | ------------------ |
| 0               | 5              | 5                    | Nginx-Frontend-SPA-CDN | (2) is not a reverse proxy | 5/5      | 2220 -> 2224       |
| 1               | 12             | 5                    | Nginx-Frontend-SPA-CDN | (2) is not a reverse proxy | 6/12     | 2226 -> 2237       |
| 2               | 7              | 6                    |                        |                            | 1/7      | 2225, 2238 -> 2243 |
| 3               | 7              | 6                    |                        |                            | 0/7      |                    |
| 4               | 7              | 6                    |                        |                            | 0/7      |
| 5               | 7              | 6                    |                        |                            | 0/7      |
| 6               | 7              | 6                    |                        |                            | 0/7      |
| 7               | 7              | 6                    |                        |                            | 0/7      |
| 8               | 7              | 6                    |                        |                            | 0/7      |
| 9               | 7              | 6                    |                        |                            | 0/7      |
| 10              | 7              | 6                    |                        |                            | 0/7      |
| 11              | 7              | 6                    |                        |                            | 0/7      |
| 12              | 6              | 6                    |                        |                            | 0/6      |
