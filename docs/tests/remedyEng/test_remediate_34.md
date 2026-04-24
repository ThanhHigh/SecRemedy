# Tài liệu Kiểm thử: Remedy 34 (CIS Nginx Benchmark - Recommendation 3.4)

## Tổng quan

Recommendation 3.4 yêu cầu forward thông tin client IP về upstream bằng `proxy_set_header`. Plugin [Remediate34](../../../core/remedyEng/recommendations/remediate_34.py) là remediation có input tùy chọn `proxy_pass` và sẽ add/upsert header vào block proxying.

## Nguyên tắc kiểm thử độc lập

- Kiểm thử theo mock remediation payload cho từng context add/add_directive.
- Không phụ thuộc scanner/parser runtime hoặc validate nginx config runtime.
- Với `proxy_pass` input, test phải phản ánh validator hiện tại (chấp nhận chuỗi có `://` hoặc `unix:`).

## Mục tiêu kiểm thử

- Xác nhận `proxy_pass` input nếu được truyền phải đúng format `http://`, `https://` hoặc `unix:`.
- Xác nhận plugin thêm đủ 3 header: `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`.
- Xác nhận plugin giữ `proxy_pass` đồng bộ với user input nếu được cung cấp.
- Xác nhận chỉ location block có proxying được thay đổi.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` lấy remediation của rule 3.4.
2. `read_child_ast_config()` lấy AST của file có vi phạm.
3. `_validate_user_inputs()` kiểm tra format `proxy_pass` nếu user nhập.
4. `remediate()` tìm context của block mục tiêu bằng `_relative_context()`.
5. `ASTEditor.get_child_ast_config()` lấy target list để upsert header.
6. `_upsert_proxy_header()` thêm hoặc replace từng header theo tên.
7. `_upsert_proxy_pass()` đồng bộ proxy target nếu người dùng nhập input.

## Tiêu chí valid

- `http://backend:8080`, `https://backend.example.com`, `unix:/tmp/backend.sock` đều hợp lệ.
- `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;` là chuẩn.
- `proxy_set_header X-Real-IP $remote_addr;` và `proxy_set_header X-Forwarded-Proto $scheme;` là chuẩn.

## Tiêu chí invalid

- `backend:8080` không có protocol là không hợp lệ.
- `ftp://...` hiện được validator chấp nhận về mặt format; có thể để case hardening kỳ vọng riêng.
- Thiếu một trong ba header chính là không đạt mục tiêu kiểm thử.
- Add header vào block không có liên quan đến proxy_pass là không đúng phạm vi.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` cho input hợp lệ và không hợp lệ.
- Kiểm tra `remedy_input_require` mô tả đúng `proxy_pass`.

### Mutation correctness
- Add 3 header vào location block có proxy_pass.
- Replace header đã tồn tại bằng args mới.
- Đồng bộ proxy_pass theo input user.

### Safety / edge cases
- Input trống phải không làm hỏng AST.
- Context rỗng hoặc target không phải list phải được bỏ qua an toàn.
- Multi-file scan result chỉ mutate file có vi phạm.

## Checklist xác minh

- `child_ast_modified` có đủ 3 `proxy_set_header` cần thiết.
- Nếu có `proxy_pass` input thì directive đó phải phản ánh đúng giá trị user nhập.
- AST sau sửa vẫn giữ nguyên location và proxy block hợp lệ.
- Diff cho thấy đúng header đã được add/upsert.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra guide detail mô tả proxy header forwarding.

### Nhóm B. Input validation / proxy_pass (4-10)
4. `http://backend:8080` hợp lệ.
5. `https://backend.example.com` hợp lệ.
6. `unix:/tmp/backend.sock` hợp lệ.
7. Input rỗng, auto-detect từ scan result.
8. Input `backend:8080` bị từ chối.
9. Input `ftp://server` bị từ chối.
10. Input chỉ khoảng trắng bị từ chối.

### Nhóm C. Header mutation correctness (11-24)
11. Add `X-Forwarded-For`.
12. Add `X-Real-IP`.
13. Add `X-Forwarded-Proto`.
14. Replace `X-Forwarded-For` khi đã tồn tại.
15. Replace `X-Real-IP` khi đã tồn tại.
16. Replace `X-Forwarded-Proto` khi đã tồn tại.
17. Giữ đúng thứ tự header trong block.
18. Giữ `proxy_pass` hiện có nếu input rỗng.
19. Upsert `proxy_pass` khi user nhập giá trị mới.
20. Không tạo duplicate `proxy_set_header` cùng tên.
21. Không đổi header ngoài 3 header rule yêu cầu.
22. Chỉ update block có `proxy_pass`.
23. Block không có `proxy_pass` vẫn có thể được upsert khi scan result yêu cầu add.
24. Mixed http/server/location blocks target đúng block.

### Nhóm D. Context / safety (25-34)
25. Context rỗng không mutate.
26. Context lệch nhưng target list tìm được vẫn an toàn.
27. Nhiều file, chỉ file có violation sửa.
28. File path normalize khác kiểu vẫn match đúng.
29. AST root list không bị chèn sai.
30. `child_ast_modified` độc lập với input AST.
31. Scan result action ngoài add/add_directive bỏ qua.
32. Scan result directive khác `proxy_set_header` bỏ qua.
33. Target không phải list bị skip an toàn.
34. Diff chỉ thể hiện proxy header changes.

### Nhóm E. Regression / edge (35-40)
35. Remediate lặp lại không tạo header trùng.
36. Nhiều proxy_pass trong một file, update đúng block.
37. `X-Forwarded-For` giữ `args` user hoặc default chính xác.
38. `proxy_pass` giữ nguyên nếu đã khớp input.
39. Scan result rỗng, AST không đổi.
40. Location path không proxy vẫn giữ nguyên.
