# Tài liệu Kiểm thử: Remedy 254 (CIS Nginx Benchmark - Recommendation 2.5.4)

## Tổng quan

Recommendation 2.5.4 yêu cầu NGINX reverse proxy không làm lộ thông tin backend qua response headers. Plugin [Remediate254](../../../core/remedyEng/recommendations/remediate_254.py) là remediation tự động, không cần user input. Tùy vào upstream context, plugin sẽ chèn `proxy_hide_header` hoặc `fastcgi_hide_header` vào block phù hợp.

## Nguyên tắc kiểm thử độc lập

- Không phụ thuộc scanner runtime; remediation payload được mock trực tiếp trong test.
- Contract cần giữ thống nhất:
	- `child_scan_result[file] = [{action, directive, context, args, logical_context}]`
	- `child_ast_config[file]["parsed"] = [...]`
- Assert chính trên `child_ast_modified[file]["parsed"]` và không có insertion vào root parsed list.

## Mục tiêu kiểm thử

- Xác nhận rule 2.5.4 được xử lý tự động, không yêu cầu nhập liệu từ người dùng.
- Xác nhận plugin chèn đúng header hiding directive theo loại upstream: `proxy_pass` hoặc `fastcgi_pass`.
- Xác nhận plugin không chèn directive vào parsed root list.
- Xác nhận `BaseRemedy._relative_context()` và fallback logic của plugin chọn đúng block đích khi scan context bị thiếu hoặc lệch.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính của plugin:

1. `read_child_scan_result()` gom remediation của rule 2.5.4 theo file.
2. `read_child_ast_config()` lấy AST của file có vi phạm.
3. `remediate()` deep-copy AST và duyệt từng remediation.
4. Chỉ xử lý `action` thuộc `add` hoặc `add_directive`.
5. Chỉ xử lý `directive` thuộc `proxy_hide_header` hoặc `fastcgi_hide_header`.
6. `_relative_context()` rút context về vị trí target trong `parsed`.
7. `_resolve_target_contexts()` tìm target an toàn từ context, từ parent block chứa `proxy_pass`/`fastcgi_pass`, hoặc từ logical context.
8. `_upsert_hide_header()` chèn directive nếu header tương ứng chưa tồn tại.

## Tiêu chí valid

- Với `proxy_pass`, hợp lệ khi chèn `proxy_hide_header X-Powered-By;` và `proxy_hide_header Server;`.
- Với `fastcgi_pass`, hợp lệ khi chèn `fastcgi_hide_header X-Powered-By;`.
- Directive có thể nằm trong `http`, `server`, hoặc `location` block nếu upstream directive nằm trong block đó.
- Nếu directive tương đương đã tồn tại, plugin không được tạo bản sao trùng lặp.

## Tiêu chí invalid

- Action ngoài `add` hoặc `add_directive` phải bị bỏ qua.
- Directive ngoài `proxy_hide_header` hoặc `fastcgi_hide_header` phải bị bỏ qua.
- Target context trỏ về parsed root list là không hợp lệ cho insertion.
- Remediation không được chèn directive vào block không có upstream tương ứng.
- Header name rỗng, args rỗng, hoặc args không phải list phải bị bỏ qua an toàn.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra class kế thừa `BaseRemedy`.
- Kiểm tra `has_input == False`.
- Kiểm tra `remedy_guide_detail` mô tả đúng proxy/fastcgi hide header behavior.

### Mutation correctness
- Add `proxy_hide_header X-Powered-By;` trong proxy block.
- Add `proxy_hide_header Server;` trong proxy block.
- Add `fastcgi_hide_header X-Powered-By;` trong fastcgi block.
- Không tạo duplicate nếu header tương ứng đã tồn tại.
- Giữ nguyên các directive khác trong cùng block.

### Safety / edge cases
- Context rỗng phải fallback sang parent block chứa `proxy_pass` hoặc `fastcgi_pass`.
- Logical context `http`, `server`, `location` phải tìm đúng block tương ứng khi scan context hỏng.
- Không chèn vào root list.
- Multi-file scan result: chỉ file có violation được sửa.
- File path normalize khác kiểu vẫn phải match đúng file.

## Checklist xác minh

- `child_ast_modified` chỉ xuất hiện cho file có violation.
- Directive được chèn đúng theo loại upstream.
- Không có bản sao trùng header tương đương.
- AST sau sửa vẫn giữ nguyên cấu trúc hợp lệ.
- Diff thể hiện đúng header hiding directives đã thêm.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == False`.
3. Kiểm tra guide detail mô tả đúng rule 2.5.4.

### Nhóm B. Valid proxy_pass cases (4-12)
4. `proxy_pass` trong `location` block với `proxy_hide_header X-Powered-By;`.
5. `proxy_pass` trong `location` block với `proxy_hide_header Server;`.
6. `proxy_pass` trong `server` block với cả 2 proxy hide headers.
7. `proxy_pass` trong `http` block với cả 2 proxy hide headers.
8. `proxy_pass` có nested location, target được chọn đúng.
9. `proxy_pass` cùng directive khác vẫn giữ đúng target.
10. `proxy_hide_header` đã tồn tại, không tạo duplicate.
11. `proxy_hide_header` có args hợp lệ một phần, vẫn giữ directive cũ.
12. `proxy_hide_header` tồn tại cho header khác, không bị thay đổi.

### Nhóm C. Valid fastcgi_pass cases (13-18)
13. `fastcgi_pass` trong `location` block với `fastcgi_hide_header X-Powered-By;`.
14. `fastcgi_pass` trong `server` block với `fastcgi_hide_header X-Powered-By;`.
15. `fastcgi_pass` trong `http` block với `fastcgi_hide_header X-Powered-By;`.
16. `fastcgi_hide_header` đã tồn tại, không tạo duplicate.
17. `fastcgi_pass` nested trong location sâu hơn, target vẫn đúng.
18. `fastcgi_hide_header` chỉ áp dụng khi upstream là fastcgi.

### Nhóm D. Invalid payload / skip behavior (19-26)
19. Action ngoài `add`/`add_directive` bị bỏ qua.
20. Directive ngoài `proxy_hide_header`/`fastcgi_hide_header` bị bỏ qua.
21. Args rỗng bị bỏ qua an toàn.
22. Args không phải list bị bỏ qua an toàn.
23. Args không có header name string bị bỏ qua.
24. Header name rỗng bị bỏ qua.
25. Remediation không có `context` hợp lệ vẫn không làm hỏng AST.
26. Remediation trỏ sai logical_context nhưng vẫn không chèn root.

### Nhóm E. Context resolution / safety (27-34)
27. `_relative_context()` từ context có `parsed` prefix map đúng target.
28. `_relative_context()` với relative path sẵn có giữ nguyên.
29. `_resolve_target_contexts()` fallback sang parent block chứa `proxy_pass`.
30. `_resolve_target_contexts()` fallback sang parent block chứa `fastcgi_pass`.
31. Logical context `http` chọn đúng `http` block.
32. Logical context `server` chọn đúng `server` block.
33. Logical context `location` chọn đúng `location` block.
34. Root parsed list không được chèn directive.

### Nhóm F. Multi-file / regression / diff (35-40)
35. Multi-file scan result chỉ file có vi phạm được mutate.
36. File path normalize khác kiểu vẫn match đúng file.
37. Remediate lặp lại không tạo duplicate hide_header.
38. AST sau sửa vẫn hợp lệ crossplane.
39. Diff chỉ thể hiện thay đổi ở block mục tiêu.
40. `child_ast_modified` chứa đúng file đã được sửa.
