# Tài liệu Kiểm thử: Remedy 242 (CIS Nginx Benchmark - Recommendation 2.4.2)

## Tổng quan

Recommendation 2.4.2 yêu cầu tạo server block mặc định để từ chối request cho hostname không xác định. Plugin [Remediate242](../../../core/remedyEng/recommendations/remediate_242.py) là remediation có user input nhưng vẫn auto-generate cấu trúc block chuẩn theo luật.

## Nguyên tắc kiểm thử độc lập

- Dùng mock `child_scan_result` và `child_ast_config`, không gọi scanner/parser runtime.
- Kiểm thử riêng hai nhánh quan trọng:
	- `add_block + directive=server` (tạo catch-all block)
	- `add/add_directive` cho `return` hoặc `ssl_reject_handshake`.
- `strict_placement` chỉ có ý nghĩa khi remediation payload có `position=0`.

## Mục tiêu kiểm thử

- Xác nhận plugin tạo hoặc cập nhật catch-all server block đúng chuẩn CIS.
- Xác nhận `server_name` mặc định là `_` khi user không nhập hoặc nhập rỗng.
- Xác nhận block mới được chèn vào `http` block, không bị chèn ở parsed root.
- Xác nhận các directive `listen`, `server_name`, `ssl_reject_handshake`, `return 444` đều xuất hiện đúng.

## Cách hoạt động dựa trên BaseRemedy

Luồng của plugin dựa trên `BaseRemedy` và `ASTEditor` như sau:

1. `read_child_scan_result()` lấy danh sách remediations của rule 2.4.2.
2. `read_child_ast_config()` lấy AST của file bị ảnh hưởng.
3. `_validate_user_inputs()` kiểm tra `server_name` và chuẩn hóa mặc định thành `_`.
4. `remediate()` tìm `http` block bằng `_find_block_contexts()`.
5. Nếu scan result trỏ sai context, plugin vẫn fallback về `http` block để chèn block đúng chỗ.
6. `_build_default_server_block()` dựng server block đầy đủ.
7. `ASTEditor.insert_to_context()` hoặc `append_to_context()` đưa block vào AST.

## Tiêu chí valid

- `server_name` rỗng hoặc không được truyền vào thì dùng `_`.
- `server_name == "_"` là hợp lệ.
- `listen 80 default_server;`, `listen [::]:80 default_server;`, `listen 443 ssl default_server;`, `listen 443 quic default_server;` đều phải xuất hiện trong block chuẩn.
- `return 444;` và `ssl_reject_handshake on;` phải có mặt.

## Tiêu chí invalid

- `server_name` khác `_` phải bị từ chối vì không còn là catch-all.
- Block chèn vào parsed root thay vì http block là không hợp lệ.
- Thiếu `return 444;` hoặc thiếu `ssl_reject_handshake on;` là không đạt.
- Chỉ có một phần block, ví dụ thiếu IPv6 listen, không đủ để coi là remediation hoàn chỉnh.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` với input rỗng, `_`, và hostname cụ thể.
- Kiểm tra `remedy_guide_detail` mô tả đúng catch-all behavior.

### Mutation correctness
- Thêm mới catch-all block vào `http` block trống.
- Cập nhật block hiện có khi đã có server mặc định.
- Kiểm tra thứ tự chèn khi `strict_placement` được bật.

### Safety / edge cases
- Context violation trỏ tới parsed root phải fallback vào `http`.
- File có nhiều `http` block thì chỉ block đầu hoặc block đúng được dùng theo logic hiện tại.
- AST không được chèn vào vị trí root list.

## Checklist xác minh

- `child_ast_modified` có block `server` mới hoặc đã cập nhật.
- `server_name` luôn là `_` nếu user không nhập đúng.
- Bảng directive trong block đúng thứ tự logic, không thiếu directive bắt buộc.
- Diff sau remediation thể hiện rõ block catch-all được thêm vào `http`.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra `remedy_input_require` và guide detail đúng rule 2.4.2.

### Nhóm B. Input validation (4-12)
4. Input rỗng, auto default `server_name _`.
5. Input chỉ khoảng trắng, auto default `_`.
6. Input `_`, hợp lệ.
7. Input hostname cụ thể `example.com`, bị từ chối.
8. Input `admin.local`, bị từ chối.
9. Input `*.example.com`, bị từ chối vì không phải catch-all.
10. Input có ký tự lạ, bị từ chối.
11. Input nhiều token, chỉ `_` mới hợp lệ.
12. `_validate_user_inputs()` giữ nguyên `_` nếu user nhập đúng.

### Nhóm C. Block composition (13-22)
13. Tạo server block chuẩn từ AST trống trong `http`.
14. Tạo block với `listen 80 default_server;`.
15. Tạo block với `listen [::]:80 default_server;`.
16. Tạo block với `listen 443 ssl default_server;`.
17. Tạo block với `listen [::]:443 ssl default_server;`.
18. Tạo block với `listen 443 quic default_server;`.
19. Tạo block với `listen [::]:443 quic default_server;`.
20. Có `server_name _;`.
21. Có `ssl_reject_handshake on;`.
22. Có `return 444;`.

### Nhóm D. Placement and fallback (23-31)
23. Context trỏ root list, fallback sang `http`.
24. Context trỏ `server`, vẫn chèn vào `http` block.
25. Nhiều `http` block, chọn block đúng theo AST.
26. `strict_placement=False`, append an toàn (kể cả khi payload có `position=0`).
27. `strict_placement=True` và payload có `position=0`, insert đầu block.
28. Block đã tồn tại, upsert thay vì duplicate.
29. Scan result thiếu `logical_context`, fallback vẫn hoạt động.
30. Scan result có context lệch, plugin vẫn tìm `http`.
31. Child AST chưa có `http`, plugin không chèn sai root.

### Nhóm E. Safety / diff / multi-file (32-40)
32. Multi-file scan result: chỉ file có violation được sửa.
33. File không có `child_scan_result` thì không mutate.
34. AST sau remediation vẫn hợp lệ crossplane structure.
35. Server block mới không phá block hiện có.
36. Diff phản ánh đầy đủ 1 block server mới.
37. File path normalize khác kiểu vẫn match đúng.
38. Chỉ user input `_` mới được xem là valid explicit value.
39. Duplicate server block không xuất hiện khi remediate lặp lại.
40. `child_ast_modified` chứa đúng file được thay đổi.
