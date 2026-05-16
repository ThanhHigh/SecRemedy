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

## Test case distributions:

| No. compliances | Test case IDs      | No. test cases | No. presets involved | Preset not involved    | Reason for not involved    | Progress |
| :-------------- | ------------------ | -------------- | :------------------- | :--------------------- | -------------------------- | -------- |
| 0               | 2220 -> 2224       | 5              | 5                    | Nginx-Frontend-SPA-CDN | (2) is not a reverse proxy | 5/5      |
| 1               | 2226 -> 2237       | 12             | 5                    | Nginx-Frontend-SPA-CDN | (2) is not a reverse proxy | 12/12    |
| 2               | 2225, 2238 -> 2239 | 3              | 6                    |                        |                            | 3/3      |
| 3               | 2240 -> 2242       | 3              | 6                    |                        |                            | 0/3      |
| 4               | 2243 -> 2245       | 3              | 6                    |                        |                            | 0/3      |
| 5               | 2246 -> 2248       | 3              | 6                    |                        |                            | 0/3      |
| 6               | 2249 -> 2251       | 3              | 6                    |                        |                            | 0/3      |
| 7               | 2252 -> 2254       | 3              | 6                    |                        |                            | 0/3      |
| 8               | 2255 -> 2257       | 3              | 6                    |                        |                            | 0/3      |
| 9               | 2258 -> 2260       | 3              | 6                    |                        |                            | 0/3      |
| 10              | 2261 -> 2263       | 3              | 6                    |                        |                            | 0/3      |
| 11              | 2264 -> 2266       | 3              | 6                    |                        |                            | 0/3      |
| 12              | 2267 -> 2272       | 6              | 6                    |                        |                            | 0/6      |
