# Ghi chú trao đổi về dự án **SecRemedy**

Ngày **27/03/2026** - **Tuần 2**

## I. Bản chất của CIS Nginx Benchmark

### 1. Hardening (Thắt chặt bảo mật) vs. Sửa lỗi cấu hình

- **Mục tiêu chính:** Đây là tập hợp các **Khuyến nghị (Recommendations)** phục vụ cho mục đích thắt chặt bảo mật (Hardening) hệ thống, không đơn thuần là sửa lỗi cấu hình (config bug fixing).
- **Tính chất:** Các khuyến nghị của CIS thường mang tính "Best Practice". Một server Nginx vẫn có thể hoạt động bình thường ngay cả khi không tuân thủ đầy đủ các khuyến nghị này, nhưng sẽ tồn tại các rủi ro về mặt an ninh thông tin.

### 2. Thuật ngữ Recommendation

- Việc sử dụng từ "Recommendation" thay vì "Requirement" phản ánh đúng bản chất của Hardening: Khuyến khích thực hiện nhưng cho phép tuân thủ linh hoạt dựa trên nhu cầu nghiệp vụ thực tế.

## II. Phân tích Cấu trúc Khuyến nghị: Triết lý Phòng thủ (Rationales) & Tác động (Impacts)

Mỗi khuyến nghị của CIS Benchmark đều được xây dựng dựa trên sự cân bằng giữa **Lý do căn bản (Rationale) - Việc tại sao phải phòng thủ**, và **Tác động (Impact) - Rủi ro khi áp dụng**. Các thành viên cần nắm được các nguyên lý này:

### 1. Tính Bổ trợ (Complementary)

- Các khuyến nghị được thiết kế để **bổ trợ lẫn nhau**, tạo ra các lớp phòng thủ chiều sâu (Defense in Depth).
- **Nguyên tắc:** Việc áp dụng đồng thời nhiều khuyến nghị sẽ gia tăng đáng kể mức độ an toàn mà không làm giảm hiệu năng hệ thống một cách không cần thiết.

### 2. Xung đột và Loại trừ lẫn nhau (Conflict & Mutual Exclusive)

- **Xung đột (Conflict):** Một số cấu hình có thể gây ảnh hưởng tiêu cực đến các tính năng khác của server hoặc ứng dụng (ví dụ: giới hạn buffer quá thấp có thể làm treo các yêu cầu tải file lớn).
- **Loại trừ lẫn nhau (Mutual Exclusive):** Các trường hợp hiếm gặp khi áp dụng khuyến nghị này sẽ trực tiếp ngăn cản việc triển khai khuyến nghị kia.

### 3. Các Triết lý Phòng thủ Cốt lõi (Dựa trên khảo sát Rationale Statements)

Qua việc phân tích `Rationales.md`, toàn bộ 44 khuyến nghị không tồn tại song song rời rạc mà cùng phục vụ cho **5 triết lý phòng thủ** chính nhằm chống lại các Vector tấn công phổ biến trên Nginx:

- **Giảm thiểu Bề mặt Tấn công (Attack Surface Reduction):** Xóa bỏ các Module không dùng (2.1.1), chỉ cho phép các HTTP Methods thực sự cần như GET/POST (5.1.2), và chỉ lắng nghe trên các port (2.4.1) đã được thẩm định. Càng ít tính năng, nguy cơ bị lợi dụng càng thấp.
- **Ngăn chặn Rò rỉ Thông tin (Information Disclosure Prevention):** Tắt server tokens (2.5.1), ẩn version Nginx khỏi custom error pages (2.5.2) và chặn quyền truy cập vào các hidden files (2.5.3) loại bỏ các manh mối mà Attacker dùng để Reconnaissance và chuẩn bị payload khai thác.
- **Chống Cạn kiệt Tài nguyên (DoS/DDoS Mitigation):** Các cuộc tấn công Slow-read hoặc flood được ngăn chặn cực kì hiệu quả nhờ việc thiết lập thời gian timeout ngắn (2.4.3, 5.2.1), khóa khắt khe các giới hạn buffer/body payload (5.2.2, 5.2.3) và Rate-Limit chặt chẽ (5.2.5).
- **Ngăn chặn Leo thang Đặc quyền (Privilege Escalation & Lateral Movement):** Giam Nginx worker trong một account không có đặc quyền (non-privileged) và bị khóa shell (2.2.1, 2.2.2, 2.2.3), đồng thời đảm bảo mọi file config nhạy cảm chỉ được sửa bởi root (2.3.1). Điều này đảm bảo nếu ứng dụng web bị hack, hacker không thể lây nhiễm sang OS.
- **Bảo mật Dữ liệu Truyền tải (Data-in-Transit Integrity):** Ưu tiên độc tôn TLS 1.3 và mTLS (4.x.x) loại bỏ hoàn toàn các phương thức mã hóa cổ điển có thể bị Man-in-the-Middle (MitM) và bẻ khóa thông qua downgrade attacks (ngăn bằng HSTS 4.1.8).

---

### 4. Phân loại rủi ro từ Impact Statements (Dựa trên khảo sát các Khuyến nghị)

Qua việc phân tích `Impacts.md`, các rủi ro (Impacts) khi áp dụng cấu hình tự động được phân thành 4 nhóm cảnh báo cốt lõi mà Engine cần truyền đạt cho người dùng:

- **Gián đoạn Dịch vụ & Kết nối (Outage & Connectivity Risks):**
  - Việc ép buộc dùng **TLS 1.3 (4.1.5)** sẽ từ chối các client/API cũ.
  - Kích hoạt **OCSP Stapling (4.1.7)** hoặc **mTLS (4.1.9, 4.1.10)** nếu sai cấu hình hoặc chứng chỉ (certificate) hết hạn sẽ gây từ chối kết nối hoàn toàn.
  - Bật **HSTS (4.1.8)** sẽ khóa tên miền ở giao thức HTTPS trong thời gian dài (khó có đường lùi nếu hệ thống con chưa sẵn sàng).
- **Phá vỡ Tính năng Ứng dụng (Functionality Breakage):**
  - **Giới hạn Request/Buffer (5.x):** Đặt `client_body_size` hoặc `large_client_header_buffers` quá khắt khe sẽ gây lỗi `413 Payload Too Large` khi upload file, hoặc lỗi `400 Bad Request` với các hệ thống auth mang header lớn (OAuth/SAML).
  - Khóa truy cập thư mục ẩn (2.5.3) nếu cấu hình sai thứ tự sẽ chặn quy trình xác thực chứng chỉ của **Let's Encrypt** (thư mục `.well-known`).
  - Strict **CSP (5.3.2)** có nguy cơ vô hiệu hóa các luồng script giao diện, làm sập Frontend của ứng dụng thật.
- **Rủi ro Cạn kiệt Tài nguyên (Resource Exhaustion):**
  - Các khuyến nghị về **Logging (3.1, 3.2, 3.3)** bắt buộc bật log chi tiết. Nếu hệ thống của khách hàng không có cơ chế `logrotate` tốt, ổ cứng lưu trữ sẽ bị đầy nhanh chóng, dẫn đến treo Nginx.
- **Chặn nhầm Người dùng Hợp lệ (False Positives in Access Control):**
  - **Rate Limit (5.2.4, 5.2.5)** cấu hình global tĩnh sẽ chặn toàn bộ lượng người dùng lớn đằng sau chung một đường mạng NAT/CG-NAT (ví dụ: mạng công ty, trường học).

## III. Phạm vi & Định hướng triển khai Dự án

### 1. Điều chỉnh Scope: Bỏ TVS (Total Violence Score)

#### 1.1. Bối cảnh

Trong giai đoạn thiết kế ban đầu, nhóm đã từng đề xuất xây dựng tính năng **TVS (Total Violence Score)** — một hệ thống tính điểm dùng để **xếp hạng mức độ ưu tiên và đề xuất thứ tự áp dụng** các khuyến nghị CIS. Ý tưởng gốc là: Nếu một số khuyến nghị "xung đột" hoặc "loại trừ" lẫn nhau, thì cần một thuật toán đánh trọng số (weighted scoring) để giúp người dùng chọn khuyến nghị nào nên áp dụng trước, khuyến nghị nào nên bỏ qua hoặc hoãn lại.

Tuy nhiên, sau khi phân tích toàn bộ **44 Rationale Statements** và **44 Impact Statements** từ CIS Nginx Benchmark v3.0.0, nhóm kết luận rằng TVS là **dư thừa về mặt lý luận** và việc bỏ nó ra khỏi scope là một quyết định hợp lý. Luận chứng dựa trên hai tiền đề cốt lõi:

> **Tiền đề 1:** Các khuyến nghị CIS được thiết kế **bổ trợ lẫn nhau** (Complementary by Design).
> **Tiền đề 2:** Các khuyến nghị CIS **không loại trừ lẫn nhau** (Non-Mutually-Exclusive).

Khi cả hai tiền đề đều đúng, **thứ tự áp dụng không ảnh hưởng đến trạng thái cuối cùng của hệ thống**, do đó một scoring system để tính toán thứ tự tối ưu là không có giá trị quyết định (decision-theoretic value).

---

#### 1.2. Tiền đề 1 — Tính Bổ trợ (Complementary by Design)

**Luận điểm:** Các khuyến nghị CIS hoạt động trên **các chiều phòng thủ trực giao** (orthogonal defense dimensions). Việc áp dụng khuyến nghị ở chiều A không làm suy yếu hay trùng lặp với khuyến nghị ở chiều B, mà ngược lại, **gia tăng chiều sâu phòng thủ tổng thể** (Defense in Depth).

Qua phân tích Rationale Statements (xem Mục II.3), toàn bộ 44 khuyến nghị phục vụ cho 5 triết lý phòng thủ hoạt động trên các lớp (layers) khác nhau của hệ thống:

| #   | Triết lý Phòng thủ        | Lớp hệ thống      | Các Khuyến nghị Tiêu biểu  | Bảo vệ chống lại                    |
| --- | ------------------------- | ----------------- | -------------------------- | ----------------------------------- |
| 1   | Giảm bề mặt tấn công      | Application Layer | 2.1.1, 2.4.1, 5.1.2        | Reconnaissance, Unauthorized Access |
| 2   | Ngăn rò rỉ thông tin      | Response Layer    | 2.5.1, 2.5.2, 2.5.3, 2.5.4 | Information Disclosure              |
| 3   | Chống cạn kiệt tài nguyên | Connection Layer  | 2.4.3, 2.4.4, 5.2.x        | DoS/DDoS                            |
| 4   | Ngăn leo thang đặc quyền  | OS/Process Layer  | 2.2.x, 2.3.x               | Privilege Escalation                |
| 5   | Bảo mật truyền tải        | Transport Layer   | 4.x.x                      | MitM, Downgrade Attacks             |

**Quan sát chính:** Không có hai triết lý nào hoạt động trên cùng một lớp hệ thống theo cách mâu thuẫn. Ví dụ:

- Tắt `server_tokens` (2.5.1 — Response Layer) không ảnh hưởng đến việc ép buộc TLS 1.3 (4.1.4 — Transport Layer).
- Giới hạn kết nối/IP (5.2.4 — Connection Layer) không xung đột với việc khóa service account (2.2.2 — OS Layer).
- Bật JSON logging (3.1 — Observability) hoạt động song song với tất cả các lớp khác mà không cần bất cứ điều kiện tiên quyết nào.

→ **Kết luận Tiền đề 1:** Các khuyến nghị mang tính **cộng tính** (additive). Mỗi khuyến nghị được áp dụng sẽ gia tăng compliance score một cách **tuyến tính** và **độc lập**, không phụ thuộc vào việc các khuyến nghị khác đã được áp dụng hay chưa.

---

#### 1.3. Tiền đề 2 — Không Loại trừ Lẫn nhau (Non-Mutually-Exclusive)

**Luận điểm:** Không tồn tại bất kỳ cặp khuyến nghị nào mà việc áp dụng khuyến nghị X **trực tiếp ngăn cản** việc áp dụng khuyến nghị Y (tức là không có quan hệ nhị phân loại trừ `X ⊕ Y`).

Qua khảo sát toàn bộ 44 Impact Statements (`Impacts.md`), nhóm xác nhận rằng **tất cả các "xung đột" được ghi nhận đều mang tính vận hành (operational), không mang tính logic (logical)**. Cụ thể:

**a) Xung đột Vận hành (Operational Conflicts) — Giải quyết được bằng tham số:**

Đây là các trường hợp khi một khuyến nghị _có thể_ gây ảnh hưởng tiêu cực nếu cấu hình sai giá trị, nhưng **luôn tồn tại một giá trị tối ưu** cho phép cả hai khuyến nghị cùng tồn tại:

| Cặp Khuyến nghị                                           | Dạng "Xung đột"                    | Tại sao KHÔNG phải Mutual Exclusive                                                                              |
| --------------------------------------------------------- | ---------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| 2.5.3 (Chặn hidden files) ↔ Let's Encrypt (`.well-known`) | Chặn dot-file sẽ phá Let's Encrypt | Giải quyết bằng **exception rule** đặt trước deny rule. Cả hai cùng tồn tại.                                     |
| 5.2.2 (Giới hạn body size) ↔ Upload file lớn              | Body size quá nhỏ → lỗi 413        | Giải quyết bằng **điều chỉnh giá trị** `client_max_body_size` phù hợp. Khuyến nghị vẫn được áp dụng.             |
| 5.2.4 (Giới hạn kết nối/IP) ↔ NAT/CG-NAT users            | Limit quá thấp → chặn nhầm         | Giải quyết bằng **điều chỉnh ngưỡng** limit phù hợp với đối tượng người dùng.                                    |
| 4.1.5 (TLS 1.3 only) ↔ Legacy clients                     | Client cũ không kết nối được       | Đây là **trade-off có chủ đích** (intentional), không phải loại trừ. Admin chọn giá trị `ssl_protocols` phù hợp. |

**b) Không tồn tại Xung đột Logic (No Logical Conflicts):**

Xung đột logic (Mutual Exclusive) xảy ra khi: _"Áp dụng X buộc phải **tắt vĩnh viễn** Y"_. Ví dụ giả định: Nếu bật `server_tokens on` là điều kiện bắt buộc của khuyến nghị A, nhưng đồng thời khuyến nghị B yêu cầu `server_tokens off`, thì A và B sẽ loại trừ nhau.

Trong **toàn bộ 44 khuyến nghị CIS Nginx**, không tồn tại trường hợp nào như vậy. Mỗi khuyến nghị kiểm soát một directive hoặc một tập directive **riêng biệt**, hoặc nếu cùng chia sẻ directive (ví dụ: nhiều rule cùng liên quan đến `ssl_protocols`), thì giá trị khuyến nghị luôn **hội tụ về cùng một hướng** (ví dụ: đều yêu cầu `TLSv1.3`).

→ **Kết luận Tiền đề 2:** Mọi khuyến nghị CIS đều có thể được áp dụng **đồng thời** trên cùng một hệ thống mà không cần loại bỏ hay hy sinh bất kỳ khuyến nghị nào.

---

#### 1.4. Kết luận: TVS không có giá trị quyết định

Từ hai tiền đề trên, ta rút ra hệ quả trực tiếp:

1. **Tính bổ trợ (Tiền đề 1)** → Trạng thái cuối cùng của server **không phụ thuộc vào thứ tự** áp dụng. Dù áp dụng khuyến nghị 2.5.1 trước 4.1.1 hay ngược lại, kết quả tuân thủ cuối cùng là **như nhau**.
2. **Không loại trừ (Tiền đề 2)** → Không cần cơ chế "chọn bên" (triage) vì **tất cả các khuyến nghị đều có thể được áp dụng**. Không có trường hợp bật X buộc phải tắt Y.
3. **Hệ quả:** Một scoring system (TVS) thiết kế để đề xuất thứ tự ưu tiên sẽ luôn cho ra kết quả **tương đương nhau** bất kể cách xếp hạng, vì mọi hoán vị đều dẫn đến cùng một trạng thái cuối. Đây là lý do TVS **không có giá trị quyết định** (no decision-theoretic value).

**Giải pháp thay thế đơn giản hơn:** SecRemedy sẽ hiển thị trực quan danh sách các khuyến nghị chưa tuân thủ kèm theo **Impact Statement** tương ứng, giúp người dùng **tự đánh giá rủi ro** dựa trên nghiệp vụ cụ thể của họ — thay vì dựa vào một con số điểm tổng hợp (aggregate score) không phản ánh ngữ cảnh thực tế.

- **Số lượng triển khai:** Tập trung hoàn thiện toàn bộ **44 Khuyến nghị** để đảm bảo đồ án đủ khối lượng kiến thức và tính ứng dụng (Cần trao đổi thêm với giảng viên hướng dẫn).

### 2. Xử lý các Khuyến nghị cấp Hệ điều hành (OS-Level)

- Đối với các khuyến nghị liên quan đến hạ tầng hoặc OS, SecRemedy sẽ cung cấp giải pháp tư vấn và hướng dẫn cấu hình để người dùng tự thực hiện, thay vì can thiệp trực tiếp vào kernel hoặc network của server qua SSH.

### 3. Quy trình Khắc phục An toàn (Safe Remediation)

- Toàn bộ quy trình phải tuân thủ nghiêm ngặt: **Quét (Scan) -> Đề xuất -> Xem trước Diff -> Phê duyệt (Approval) -> Kiểm tra cú pháp (nginx -t) -> Áp dụng (Reload)**. Điều này đảm bảo Zero-downtime cho hệ thống của khách hàng.
