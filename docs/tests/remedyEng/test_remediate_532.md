# Tài liệu Kiểm thử: Remedy 532 (CIS Nginx Benchmark - Recommendation 5.3.2)

## Tổng quan

Recommendation 5.3.2 yêu cầu cấu hình Content Security Policy để giảm nguy cơ XSS và injection. Plugin [Remediate532](../../../core/remedyEng/recommendations/remediate_532.py) là remediation có input, cho phép dùng baseline an toàn hoặc CSP tùy chỉnh.

## Nguyên tắc kiểm thử độc lập

- Test plugin-level bằng mock remediation payload (`add`/`replace`) và mock AST.
- Không phụ thuộc scanner/parser runtime.
- Tách bạch case baseline policy, custom policy, và fallback minimal policy theo `_get_csp_policy()`.

## Mục tiêu kiểm thử

- Xác nhận policy mặc định là baseline an toàn `default-src 'self'; frame-ancestors 'self'; form-action 'self';`.
- Xác nhận custom policy được ưu tiên khi user nhập rõ ràng.
- Xác nhận `add_header Content-Security-Policy ... always;` được thêm hoặc replace đúng.
- Xác nhận plugin không tạo header sai tên hoặc thiếu `always`.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` lấy remediation của rule 5.3.2.
2. `read_child_ast_config()` lấy AST của file có vi phạm.
3. `_get_csp_policy()` quyết định policy dùng baseline hay custom.
4. `remediate()` duyệt violation và xử lý theo `action`.
5. Với `add`, plugin append directive vào parent list.
6. Với `replace`, plugin update args node hiện có.

## Tiêu chí valid

- Baseline CSP phải chứa ít nhất `default-src 'self'`, `frame-ancestors 'self'`, `form-action 'self'`.
- Custom CSP hợp lệ nếu user nhập rõ và policy phản ánh đúng chuỗi đó.
- `Content-Security-Policy` phải được add_header với `always`.

## Tiêu chí invalid

- Policy rỗng là không hợp lệ nếu không có baseline fallback hợp lệ.
- Thiếu `default-src` hoặc cấu hình quá lỏng nên được đánh dấu hardening kỳ vọng; implementation hiện tại chưa validate cú pháp CSP.
- Chèn nhầm `Content-Security-Policy-Report-Only` thay vì `Content-Security-Policy` là ngoài scope của plugin hiện tại.
- Append header ở root là không hợp lệ.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_get_csp_policy()` với baseline, custom, và input trống.
- Kiểm tra guide detail nhấn mạnh rủi ro CSP quá chặt.

### Mutation correctness
- Add CSP header với baseline mặc định.
- Replace CSP header bằng custom policy.
- Giữ đúng `always` parameter.

### Safety / edge cases
- `child_ast_modified` không thay đổi nếu input gây invalidate trên code path tương ứng.
- Context rỗng hoặc exact_path sai phải không chèn sai vị trí.
- Multi-file scan result chỉ file vi phạm được sửa.

## Checklist xác minh

- `child_ast_modified` có CSP header đúng tên và đúng policy.
- Policy baseline hoặc custom được serialize thành chuỗi args đúng format.
- Block mục tiêu vẫn hợp lệ sau mutation.
- Diff thể hiện rõ header được thêm hoặc thay thế.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra guide detail mô tả baseline và custom CSP.

### Nhóm B. Policy selection (4-12)
4. Chọn baseline khi input rỗng.
5. Chọn baseline khi user nhập `yes`.
6. Chọn custom khi user nhập policy tùy chỉnh.
7. Chọn `default-src 'self';` khi user từ chối baseline và không nhập custom.
8. Policy custom có `default-src` hợp lệ.
9. Policy custom có `frame-ancestors` hợp lệ.
10. Policy custom có `form-action` hợp lệ.
11. Policy rỗng và không có fallback, bị từ chối.
12. Policy chứa chuỗi lỗi cú pháp, bị từ chối theo kỳ vọng test.

### Nhóm C. Mutation correctness (13-25)
13. Add CSP header baseline.
14. Add CSP header custom.
15. Replace CSP header hiện có.
16. Add `always` flag.
17. Preserve other add_header directives.
18. Add trong http block.
19. Add trong server block.
20. Add trong location block.
21. Replace đúng node từ `exact_path`.
22. Add đúng parent list khi action add.
23. Không đổi header khác tên.
24. Không tạo duplicate CSP header khi remediate lặp lại.
25. Serialize policy thành string args đúng format.

### Nhóm D. Context / safety (26-34)
26. Context rỗng không chèn sai root.
27. Exact_path sai, plugin không corrupt AST.
28. Nhiều file, chỉ file vi phạm được sửa.
29. File path normalize khác kiểu vẫn match đúng.
30. Scan result directive khác add_header bỏ qua.
31. AST deep copy độc lập.
32. Diff chỉ thể hiện CSP change.
33. AST sau sửa vẫn hợp lệ.
34. `child_ast_modified` chỉ có file vi phạm.

### Nhóm E. Regression / edge (35-40)
35. Baseline CSP dùng đúng default-src/self set.
36. Custom CSP ưu tiên hơn baseline.
37. Scan result rỗng, AST không đổi.
38. Remediate lặp lại không tạo duplicate header.
39. Header được chèn đúng block mục tiêu.
40. Output không làm mất directive khác trong block.
