# Tài liệu Kiểm thử: Remedy 241 (CIS Nginx Benchmark - Recommendation 2.4.1)

## Tổng quan

Recommendation 2.4.1 yêu cầu NGINX chỉ lắng nghe trên các cổng được cho phép. Trong implementation hiện tại, plugin [Remediate241](../../../core/remedyEng/recommendations/remediate_241.py) là remediation tự động: phát hiện listen directive không hợp lệ và xóa trực tiếp các directive đó khỏi AST.

## Nguyên tắc kiểm thử độc lập

- Chỉ kiểm thử plugin-level bằng mock payload, không chạy scanner/parser/docker/ssh.
- Dùng contract thống nhất:
	- `remedy.user_inputs` (rule này để rỗng)
	- `remedy.child_scan_result = {file_path: [remediation entries]}`
	- `remedy.child_ast_config = {file_path: {"parsed": [...]}}`
- Chạy `remedy.remediate()` rồi assert trên `remedy.child_ast_modified[file_path]["parsed"]`.
- Scanner chịu trách nhiệm quyết định violation listen; plugin chỉ delete theo remediation payload hợp lệ.

## Mục tiêu kiểm thử

- Xác nhận plugin chỉ xử lý đúng rule 2.4.1 và không đụng sang directive khác.
- Xác nhận các listen directive có cổng ngoài danh sách cho phép bị xóa hoàn toàn.
- Xác nhận các cổng hợp lệ vẫn được giữ nguyên, kể cả khi có tham số đi kèm như `ssl`, `http2`, `quic`, `reuseport`.
- Xác nhận context path từ scan result được rút về relative path đúng trước khi gọi `ASTEditor.remove_by_context()`.

## Cách hoạt động dựa trên BaseRemedy

Plugin kế thừa `BaseRemedy` và dùng luồng chuẩn:

1. `read_child_scan_result()` gom các remediation của rule 2.4.1 theo file.
2. `read_child_ast_config()` lấy phần `parsed` của từng file có vi phạm.
3. `remediate()` deep-copy AST, duyệt từng violation, lọc `action == delete` và `directive == listen`.
4. `_relative_context()` chuyển context từ scan result về relative path trong `parsed`.
5. `ASTEditor.remove_by_context()` xóa node tương ứng.
6. `child_ast_modified[file_path]["parsed"]` phải là AST đã chỉnh sửa.

## Tiêu chí valid

- Mỗi remediation có `action=delete`, `directive=listen`, context map được thì node tương ứng bị xóa.
- Context không map được thì plugin bỏ qua an toàn, không làm hỏng AST.
- File không chứa violation cho rule này thì không bị thay đổi.

## Tiêu chí invalid

- `listen 8000;`, `listen 8081;`, `listen 22;` phải bị xem là vi phạm.
- `listen unix:/var/run/nginx.sock;` không phải listen theo port TCP/UDP nên không được coi là trường hợp delete theo rule này nếu scanner không gắn violation.
- Context rỗng hoặc context không map được về node hợp lệ phải không làm hỏng AST.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra class kế thừa `BaseRemedy`.
- Kiểm tra `has_input == False`.
- Kiểm tra có `id`, `title`, `description`, `audit_procedure`, `impact`, `remediation`.

### Mutation correctness
- Xóa 1 listen không hợp lệ trong server block.
- Xóa nhiều listen không hợp lệ trong cùng file nhưng khác block.
- Giữ nguyên listen hợp lệ và chỉ thay đổi node vi phạm.

### Safety / edge cases
- Violation nằm ở block lồng sâu.
- Multi-file scan result: chỉ file có violation bị thay đổi.
- Context đã là relative path thì `_relative_context()` không làm mất dữ liệu.
- AST root list không được chỉnh sửa sai vị trí.

## Checklist xác minh

- `child_scan_result` có đúng file-grouped payload cho rule 2.4.1.
- `child_ast_config` chỉ chứa các file có violation.
- `child_ast_modified` có cùng key file với file bị vi phạm.
- Sau remediation, các directive `listen` trái phép biến mất, directive hợp lệ vẫn còn.
- Diff sinh ra từ AST phải phản ánh đúng việc xóa node, không làm gãy cấu trúc `server` hoặc `http`.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra class kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == False`.
3. Kiểm tra đủ `id`, `title`, `description`, `audit_procedure`, `impact`, `remediation`.

### Nhóm B. Delete contract behavior (4-13)
4. `action=delete`, `directive=listen`, context hợp lệ -> node bị xóa.
5. Cùng file có nhiều remediation delete -> xóa đủ các node mục tiêu.
6. `action` khác delete -> bỏ qua.
7. `directive` khác listen -> bỏ qua.
8. Context rỗng -> bỏ qua an toàn.
9. Context sai kiểu -> bỏ qua an toàn.
10. `_relative_context()` nhận context có `parsed` prefix -> map đúng.
11. `_relative_context()` nhận context đã relative -> giữ nguyên.
12. Xóa node lồng trong block sâu vẫn đúng target.
13. AST không bị chèn node mới.

### Nhóm C. Invalid ports / delete behavior (14-23)
14. `listen 8000;` bị xóa.
15. `listen 8081;` bị xóa.
16. `listen 22;` bị xóa.
17. `listen 3000 ssl;` bị xóa.
18. `listen 8444 quic;` bị xóa.
19. `listen 9001;` bị xóa.
20. `listen 9999 reuseport;` bị xóa.
21. `listen 127.0.0.1:8000;` bị xóa.
22. `listen [::]:8444;` bị xóa.
23. `listen 10.0.0.1:22;` bị xóa.

### Nhóm D. Mixed and multi-violation behavior (24-31)
24. Một server block có 1 hợp lệ + 1 invalid, chỉ invalid bị xóa.
25. Một server block có 2 invalid + 1 hợp lệ, chỉ 2 invalid bị xóa.
26. Hai server block khác nhau, mỗi block 1 invalid, xóa đúng từng block.
27. Một file có nhiều `listen` ở `http` và `server`, chỉ directive vi phạm bị tác động.
28. Violation xuất hiện ở block con lồng sâu, context vẫn map đúng.
29. Nhiều violation cùng file, xóa không làm lệch index của node còn lại.
30. Scan result có action ngoài `delete`, plugin bỏ qua an toàn.
31. Scan result có directive khác `listen`, plugin bỏ qua an toàn.

### Nhóm E. Safety / path / diff (32-40)
32. Context đã là relative path, `_relative_context()` giữ nguyên hợp lệ.
33. Context có `parsed` prefix, `_relative_context()` cắt đúng phần sau `parsed`.
34. Context rỗng, plugin không chèn/xóa sai root.
35. File path có `./` và `/` khác nhau nhưng vẫn match đúng file.
36. File path dùng slash ngược vẫn được normalize.
37. Scan result cho rule khác không được mutate file này.
38. AST không bị mất block `server` sau khi xóa node.
39. `child_ast_modified` chỉ xuất hiện cho file có violation.
40. Diff cuối cùng chỉ thể hiện xóa node listen không hợp lệ.
