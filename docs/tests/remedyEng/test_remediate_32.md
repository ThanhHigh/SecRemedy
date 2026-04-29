# Tài liệu Kiểm thử: Remedy 32 (CIS Nginx Benchmark - Recommendation 3.2)

## Tổng quan

Recommendation 3.2 yêu cầu bật access logging ở các scope phù hợp. Plugin [Remediate32](../../../core/remedyEng/recommendations/remediate_32.py) là remediation có input, cho phép cấu hình log path theo scope và tuỳ chọn `log_not_found`.

## Nguyên tắc kiểm thử độc lập

- Dữ liệu đầu vào phải mock theo contract BaseRemedy (`child_scan_result`, `child_ast_config`).
- Không gọi scanner/parser runtime; chỉ test parse-scope, infer-scope và mutation hành vi plugin.
- Tách riêng test validation input và test mutation để dễ xác định nguyên nhân fail.

## Mục tiêu kiểm thử

- Xác nhận chuỗi input `scope:path format` được parse đúng thành map theo scope.
- Xác nhận log path phải là đường dẫn tuyệt đối hoặc `off`.
- Xác nhận `access_log` được add/replace đúng theo scope global / per_server / location.
- Xác nhận `log_not_found` chỉ được upsert khi input hợp lệ là `on` hoặc `off`.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` lấy remediation của rule 3.2.
2. `read_child_ast_config()` lấy AST của file có vi phạm.
3. `_validate_user_inputs()` kiểm tra `user_inputs[0]` theo dạng scope map.
4. `remediate()` gọi `_parse_scope_map()` rồi xác định scope hiện tại bằng `_infer_scope()`.
5. Nếu action là `replace`/`modify_directive`, plugin replace args của `access_log`.
6. Nếu action là `add`/`add_directive`, plugin add directive vào list tương ứng.
7. `_upsert_sibling_directive()` và `_upsert_in_block()` dùng để giữ cấu trúc AST hợp lệ.

## Tiêu chí valid

- `global:/var/log/nginx/access.log combined` là hợp lệ.
- `per_server:/var/log/nginx/site.log main_access_json` là hợp lệ.
- `location:/var/log/nginx/api.log combined` là hợp lệ.
- `off` là hợp lệ nếu intentional disable đã được scanner mô tả.

## Tiêu chí invalid

- Log path không bắt đầu bằng `/` là không hợp lệ.
- Input rỗng là không hợp lệ.
- Scope malformed phải được coi là sai format.
- `log_not_found` chỉ chấp nhận `on` hoặc `off`, giá trị khác không được upsert.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` với path tuyệt đối, path tương đối, và off.
- Kiểm tra `_parse_scope_map()` tách đúng scope-key và args.

### Mutation correctness
- Replace `access_log` tại global scope.
- Add `access_log` trong server block.
- Add `access_log` trong location block.
- Upsert `log_not_found` khi input có giá trị hợp lệ.

### Safety / edge cases
- Context depth khác nhau phải map ra scope đúng.
- File có nhiều scope khác nhau nhưng chỉ file bị violation được sửa.
- Nếu context không map được target list thì AST không bị hỏng.

## Checklist xác minh

- `child_ast_modified` phản ánh đúng scope được target.
- Path log sau remediation vẫn là absolute path hoặc `off`.
- `access_log` args được giữ đúng thứ tự.
- Diff không làm đổi các block không liên quan.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra guide detail mô tả scoped logging.

### Nhóm B. Input validation / parsing (4-13)
4. `global:/var/log/nginx/access.log combined` hợp lệ.
5. `per_server:/var/log/nginx/site.log main_access_json` hợp lệ.
6. `location:/var/log/nginx/api.log combined` hợp lệ.
7. `off` hợp lệ ở scope `global`.
8. `off` hợp lệ ở scope `per_server`.
9. `off` hợp lệ ở scope `location`.
10. Path không bắt đầu bằng `/`, bị từ chối.
11. Input rỗng, bị từ chối.
12. Scope không có trong map, fallback về default.
13. `log_not_found` nhận `on` hoặc `off`.

### Nhóm C. Mutation correctness (14-26)
14. Replace access_log global.
15. Replace access_log per_server.
16. Replace access_log location.
17. Add access_log global nếu scan result yêu cầu add.
18. Add access_log per_server nếu scan result yêu cầu add.
19. Add access_log location nếu scan result yêu cầu add.
20. Upsert `log_not_found on`.
21. Upsert `log_not_found off`.
22. Update access_log args theo scope_map ưu tiên scope cụ thể.
23. Fallback sang global khi scope-specific input không có.
24. Fallback sang default khi scope-specific và global đều không có.
25. Không thay đổi directive khác trong cùng block.
26. Nhiều access_log trong file, cập nhật đúng target.

### Nhóm D. Scope inference / context (27-34)
27. `relative_context` với block count 1 cho scope global.
28. `relative_context` với block count 2 cho scope per_server.
29. `relative_context` với block count >2 cho scope location.
30. Context rỗng không mutate.
31. Context lệch nhưng vẫn map được target list.
32. File path normalize khác kiểu vẫn match đúng.
33. Nhiều file, chỉ file có violation bị đổi.
34. AST root không bị chèn directive sai scope.

### Nhóm E. Safety / no-op / diff (35-40)
35. Scan result rỗng, AST không đổi.
36. Input invalid, `child_ast_modified` rỗng.
37. Diff chỉ phản ánh access_log/log_not_found.
38. `child_ast_modified` deep copy độc lập.
39. Remediate lặp lại không tạo duplicate directive.
40. File không có `access_log` target vẫn giữ nguyên.
