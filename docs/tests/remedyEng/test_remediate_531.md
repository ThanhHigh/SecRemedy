# Tài liệu Kiểm thử: Remedy 531 (CIS Nginx Benchmark - Recommendation 5.3.1)

## Tổng quan

Recommendation 5.3.1 yêu cầu thêm `X-Content-Type-Options: nosniff` để ngăn MIME sniffing. Plugin [Remediate531](../../../core/remedyEng/recommendations/remediate_531.py) là remediation có bước xác nhận người dùng trước khi áp dụng.

## Nguyên tắc kiểm thử độc lập

- Test độc lập bằng mock payload cho `add` và `replace`, không chạy scanner/parser runtime.
- Ưu tiên xác nhận confirmation gate trước mutation assertions.
- Bắt buộc có case payload context không hợp lệ để đảm bảo plugin không làm hỏng AST.

## Mục tiêu kiểm thử

- Xác nhận chỉ khi user xác nhận `yes/y/true/1` thì remediation mới chạy.
- Xác nhận plugin xử lý đúng cả action `add` và `replace` cho `add_header`.
- Xác nhận header được thêm với giá trị `nosniff` và có `always`.
- Xác nhận file không bị thay đổi nếu user từ chối.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` lấy remediation của rule 5.3.1.
2. `read_child_ast_config()` lấy AST của file bị vi phạm.
3. `remediate()` kiểm tra `user_inputs[0]` như một confirmation gate.
4. Nếu user đồng ý, plugin duyệt từng violation và xử lý theo `action`.
5. Với `add`, plugin append `add_header` vào parent list của `exact_path`.
6. Với `replace`, plugin update args tại node đích.

## Tiêu chí valid

- `yes`, `y`, `true`, `1` là xác nhận hợp lệ.
- `add_header X-Content-Type-Options "nosniff" always;` là cấu hình hợp lệ.
- Header có thể nằm trong `http`, `server`, hoặc `location` block.

## Tiêu chí invalid

- Bất kỳ response khác `yes/y/true/1` đều phải từ chối remediation.
- Thiếu `always` là không đạt tiêu chí kiểm thử nếu scan result yêu cầu đầy đủ.
- Chèn sai header name khác `X-Content-Type-Options` là không hợp lệ.
- Append header ở vị trí root là không hợp lệ.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra gate xác nhận người dùng.
- Kiểm tra guide nói rõ remediation chỉ chạy khi đồng ý.

### Mutation correctness
- Add header mới khi action là `add`.
- Replace header cũ khi action là `replace`.
- Giữ nguyên các header khác trong cùng block.

### Safety / edge cases
- User từ chối thì `child_ast_modified` phải rỗng.
- Context rỗng hoặc exact_path sai thì không mutate.
- Multi-file scan result: chỉ file có violation được sửa.

## Checklist xác minh

- `child_ast_modified` chỉ xuất hiện khi user đồng ý.
- `add_header` có đúng tên header và giá trị `nosniff`.
- `always` vẫn còn trong args nếu scan result yêu cầu.
- Diff phản ánh đúng thay đổi ở block mục tiêu.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra confirmation gate được mô tả trong guide.

### Nhóm B. Confirmation gate (4-10)
4. Input `yes` cho phép chạy.
5. Input `y` cho phép chạy.
6. Input `true` cho phép chạy.
7. Input `1` cho phép chạy.
8. Input `no` từ chối chạy.
9. Input `false` từ chối chạy.
10. Input rỗng từ chối chạy.

### Nhóm C. Mutation correctness (11-24)
11. Add `X-Content-Type-Options` header mới.
12. Add `nosniff` đúng giá trị.
13. Add `always` đúng flag.
14. Replace header existing value.
15. Preserve other headers in same block.
16. Add header trong http block.
17. Add header trong server block.
18. Add header trong location block.
19. Update directive khi action là `add`.
20. Update directive khi action là `replace`.
21. Không đổi header khác tên.
22. Không tạo duplicate header khi remediate lặp lại.
23. Upsert đúng node từ `exact_path`.
24. Append đúng parent list khi action add.

### Nhóm D. Context / safety (25-34)
25. User từ chối thì AST không đổi.
26. Context rỗng thì không mutate root.
27. Nhiều file, chỉ file vi phạm được sửa.
28. File path normalize khác kiểu vẫn match đúng.
29. Scan result directive khác add_header, plugin bỏ qua.
30. Exact_path sai, plugin không corrupt AST.
31. AST deep copy độc lập.
32. Diff chỉ thể hiện header security change.
33. AST sau sửa vẫn hợp lệ.
34. `child_ast_modified` chỉ tồn tại khi user đồng ý.

### Nhóm E. Regression / edge (35-40)
35. `always` vẫn còn trong args sau replace.
36. `nosniff` có thể được quote đúng format.
37. Scan result rỗng, AST không đổi.
38. Remediate lặp lại không tạo duplicate header.
39. Header được chèn đúng block mục tiêu.
40. Output không làm mất directive khác trong block.
