# Tài liệu Kiểm thử: Remedy 511 (CIS Nginx Benchmark - Recommendation 5.1.1)

## Tổng quan

Recommendation 5.1.1 yêu cầu giới hạn truy cập bằng allow/deny directive ở location block. Plugin [Remediate511](../../../core/remedyEng/recommendations/remediate_511.py) là remediation có input, dùng danh sách IP/CIDR để dựng chính sách least privilege.

## Nguyên tắc kiểm thử độc lập

- Mock trực tiếp `exact_path` và block list cần mutate trong AST.
- Không phụ thuộc scanner/parser runtime.
- Kế hoạch test phải phản ánh implementation hiện tại: parser IP hiện hỗ trợ IPv4/CIDR IPv4 theo regex, chưa hỗ trợ IPv6.

## Mục tiêu kiểm thử

- Xác nhận location path phải bắt đầu bằng `/`.
- Xác nhận danh sách IP/CIDR phải có ít nhất một giá trị hợp lệ.
- Xác nhận plugin thêm đủ `allow` directives cho từng IP hợp lệ và luôn kết thúc bằng `deny all;`.
- Xác nhận chỉ location được nhắm tới theo `exact_path` mới bị thay đổi.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` gom remediation của rule 5.1.1 theo file.
2. `read_child_ast_config()` lấy AST của file có vi phạm.
3. `_validate_user_inputs()` kiểm tra location path và danh sách IP.
4. `remediate()` deep-copy AST rồi tìm `exact_path` target.
5. `ASTEditor.get_child_ast_config()` lấy location block để append allow/deny.
6. `_parse_ips()` lọc IP/CIDR hợp lệ trước khi thêm directive.

## Tiêu chí valid

- Location path như `/admin_login` là hợp lệ.
- IP đơn như `192.168.1.100` là hợp lệ.
- CIDR như `10.0.0.0/8` là hợp lệ.
- `deny all;` luôn được thêm sau danh sách `allow`.
- Trong scope hiện tại, chỉ xét định dạng IPv4/CIDR IPv4.

## Tiêu chí invalid

- Location path không bắt đầu bằng `/` là không hợp lệ.
- IP list rỗng hoặc không parse được IP/CIDR hợp lệ là không hợp lệ.
- Nếu location block không tồn tại hoặc `exact_path` sai thì không được mutate bừa.
- Thiếu `deny all;` là không đạt yêu cầu.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` với location sai và CIDR sai.
- Kiểm tra `_parse_ips()` lọc chính xác chuỗi nhập vào.

### Mutation correctness
- Add allow directives cho nhiều IP.
- Thêm `deny all;` ở cuối location block.
- Không làm thay đổi directive không liên quan.

### Safety / edge cases
- `exact_path` không map được thì AST giữ nguyên.
- Multi-file scan result chỉ file có rule 5.1.1 bị sửa.
- Danh sách IP có phần tử không hợp lệ phải bị loại bỏ trước khi mutate.

## Checklist xác minh

- `child_ast_modified` có location block mục tiêu được cập nhật.
- Tất cả `allow` directives đứng trước `deny all;`.
- Path bảo vệ đúng như user input và không bị trộn sang location khác.
- Diff thể hiện rõ sách allow/deny đúng thứ tự.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra guide detail mô tả least privilege.

### Nhóm B. Input validation / parsing (4-12)
4. Location `/admin_login` hợp lệ.
5. Location `/api/internal` hợp lệ.
6. Location `/health-check` hợp lệ.
7. Location không bắt đầu bằng `/`, bị từ chối.
8. IP single `192.168.1.100` hợp lệ.
9. IP single `10.20.30.40` hợp lệ.
10. CIDR `10.0.0.0/8` hợp lệ.
11. CIDR `192.168.0.0/16` hợp lệ.
12. IP list rỗng hoặc không parse được, bị từ chối.

### Nhóm C. Mutation correctness (13-25)
13. Add nhiều `allow` directives.
14. Add `deny all;` ở cuối.
15. Thứ tự allow trước deny được giữ đúng.
16. Add allow + deny vào location mục tiêu.
17. Không thiếu allow nào trong list hợp lệ.
18. Không thêm IP không hợp lệ.
19. Target location nhận directive đúng path.
20. Nhiều IP, mỗi IP thành 1 allow.
21. Nhiều CIDR, mỗi CIDR thành 1 allow.
22. Do not duplicate deny all.
23. Do not disturb existing proxy_pass or root.
24. Update location đã có allow/deny sẵn.
25. Append directive vào đúng block target.

### Nhóm D. Context / safety (26-34)
26. `exact_path` đúng thì mutate location chính xác.
27. `exact_path` sai thì AST không đổi.
28. Context rỗng, không mutate sai root.
29. Nhiều file, chỉ file vi phạm được sửa.
30. File path normalize khác kiểu vẫn match đúng.
31. Scan result action không phải add, plugin bỏ qua.
32. Scan result directive khác location, plugin bỏ qua.
33. Location block không tồn tại, plugin bỏ qua an toàn.
34. Deep copy AST không alias input.

### Nhóm E. Regression / edge (35-40)
35. Scan result rỗng, AST không đổi.
36. Remediate lặp lại không tạo duplicate allow/deny.
37. Deny all vẫn là phần tử cuối.
38. Diff phản ánh allow/deny đúng thứ tự.
39. AST sau sửa vẫn hợp lệ crossplane.
40. `child_ast_modified` chỉ chứa file có violation.
