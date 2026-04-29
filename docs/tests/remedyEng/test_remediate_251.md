# Tài liệu Kiểm thử: Remedy 251 (CIS Nginx Benchmark - Recommendation 2.5.1)

## Tổng quan

Recommendation 2.5.1 yêu cầu `server_tokens` phải được đặt thành `off`. Plugin [Remediate251](../../../core/remedyEng/recommendations/remediate_251.py) là remediation tự động, chỉ cần replace directive hiện có hoặc cập nhật directive phù hợp trong AST.

## Nguyên tắc kiểm thử độc lập

- Chỉ dùng fixture unit: `user_inputs` rỗng, `child_scan_result`, `child_ast_config`.
- Không test parser/scanner runtime; chỉ test mutation của plugin theo remediation payload.
- Cần tách rõ hai expected:
	- Có `args` trong scan payload -> plugin dùng `args` đó.
	- Không có `args` hoặc `args` rỗng -> fallback `off`.

## Mục tiêu kiểm thử

- Xác nhận `server_tokens` luôn được chuẩn hóa về `off`.
- Xác nhận plugin chấp nhận action alias từ scan result như `replace`, `modify`, `modify_directive`.
- Xác nhận plugin tìm đúng context `server_tokens` trong AST và không đụng sang directive khác.
- Xác nhận các node không có `server_tokens` không bị tạo sai ở context root.

## Cách hoạt động dựa trên BaseRemedy

Luồng chuẩn của plugin:

1. `read_child_scan_result()` gom remediation của rule 2.5.1 theo file.
2. `read_child_ast_config()` lấy phần `parsed` của file.
3. `remediate()` deep-copy AST rồi duyệt từng violation.
4. `_relative_context()` chuyển context về vị trí node thật trong `parsed`.
5. Nếu có context trực tiếp, plugin replace `server_tokens`; nếu không, nó dò tất cả context của `server_tokens` bằng `_find_directive_contexts()`.
6. Sau mutation, `child_ast_modified[file_path]["parsed"]` phải chứa `server_tokens off;`.

## Tiêu chí valid

- `server_tokens off;` là trạng thái mục tiêu mặc định cho rule này.
- Directive có thể nằm trong `http` block hoặc `server` block tùy AST đầu vào.
- Nếu scanner cung cấp `args` hợp lệ khác, plugin hiện tại ưu tiên dùng `args` từ payload.

## Tiêu chí invalid

- `server_tokens on;` là không hợp lệ.
- Thiếu `server_tokens` mà plugin tạo sai ở root là không hợp lệ.
- Action không thuộc nhóm replace/modify phải bị bỏ qua.
- Directives khác như `add_header` hoặc `listen` không được thay đổi bởi rule này.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra class kế thừa `BaseRemedy`.
- Kiểm tra `has_input == False`.
- Kiểm tra comment/guide mô tả đây là remediation tự động.

### Mutation correctness
- Replace `server_tokens on;` thành `off`.
- Modify directive alias vẫn tạo kết quả giống replace.
- Nhiều `server_tokens` trong cùng AST đều được cập nhật khi scan result cho phép.

### Safety / edge cases
- Context rỗng nhưng AST có directive `server_tokens` ở nơi khác.
- File nhiều block lồng nhau.
- Scan result trống hoặc sai action thì không đổi AST.

## Checklist xác minh

- `child_ast_modified` có đúng file bị vi phạm.
- Args của `server_tokens` chỉ còn `off`.
- Không phát sinh node mới ngoài directive mục tiêu.
- Diff thể hiện replacement ngắn gọn, không tái cấu trúc block.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == False`.
3. Kiểm tra guide detail mô tả auto-remediation.

### Nhóm B. Valid states (4-13)
4. `server_tokens off;` trong http block.
5. `server_tokens off;` trong server block.
6. `server_tokens off;` khi có nhiều directive khác cạnh bên.
7. `server_tokens off;` với comment xung quanh.
8. `server_tokens off;` trong file nhiều server block.
9. `server_tokens off;` được phát hiện từ direct context.
10. `server_tokens off;` được phát hiện từ fallback `_find_directive_contexts()`.
11. Scan result cho action alias `replace`.
12. Scan result cho action alias `modify`.
13. Scan result cho action alias `modify_directive`.

### Nhóm C. Invalid states / replacement (14-23)
14. `server_tokens on;` phải được replace thành off.
15. `server_tokens ` empty args phải được normalize thành off.
16. `server_tokens` thiếu args trong scan result thì fallback `off`.
17. Context đúng nhưng directive khác, plugin bỏ qua.
18. Action khác replace/modify, plugin bỏ qua.
19. Rule khác trong scan result, plugin bỏ qua.
20. Có nhiều `server_tokens` trong 1 block, update đúng node được target.
21. Có `server_tokens` nested trong block con, vẫn update đúng.
22. File path normalize khác kiểu vẫn match đúng file.
23. Scan result thiếu args nhưng directive là `server_tokens`, plugin đưa về `off`.

### Nhóm D. Safety / no-op / multi-file (24-32)
24. Scan result rỗng, AST không đổi.
25. `child_scan_result` không có file này, AST không đổi.
26. Context rỗng nhưng AST có directive `server_tokens` ở nơi khác, không corrupt root.
27. Nhiều file cùng rule, mutate đúng file có violation.
28. AST root list không bị thêm node mới.
29. Node không phải dict bị bỏ qua an toàn.
30. `child_ast_modified` có deep copy không alias sang input.
31. Một file có cả `server_tokens` hợp lệ và không hợp lệ, update đúng directive target.
32. Diff chỉ thay args thành off, không thay đổi cấu trúc block.

### Nhóm E. Regression / edge (33-40)
33. `server_tokens off;` đã hợp lệ thì không tạo thay đổi khi scan result yêu cầu tương ứng.
34. File có nhiều directive cùng tên khác scope, update đúng scope theo context.
35. Context path dài, `_relative_context()` cắt đúng.
36. Context đã relative, `_relative_context()` giữ nguyên.
37. `server_tokens` ở http block và server block cùng file, scan result chỉ target một node.
38. Remediate lặp lại không làm đổi kết quả lần hai.
39. File path case-normalization vẫn match đúng.
40. Node `server_tokens` vẫn giữ nguyên vị trí tương đối trong block.
