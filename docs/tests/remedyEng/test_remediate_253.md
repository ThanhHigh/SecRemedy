# Tài liệu Kiểm thử: Remedy 253 (CIS Nginx Benchmark - Recommendation 2.5.3)

## Tổng quan

Recommendation 2.5.3 yêu cầu chặn truy cập các file ẩn, đồng thời vẫn phải cho phép ACME challenge của Let's Encrypt. Plugin [Remediate253](../../../core/remedyEng/recommendations/remediate_253.py) là remediation có input và nhạy cảm với thứ tự chèn block.

## Nguyên tắc kiểm thử độc lập

- Chỉ test plugin-level qua mock payload (`child_scan_result`, `child_ast_config`).
- Không phụ thuộc scanner runtime hay nginx runtime.
- Bắt buộc có case assert thứ tự: ACME location phải đứng trước deny location khi cả hai cùng tồn tại.
- Bắt buộc có case context root/invalid để kiểm tra plugin không chèn sai vào parsed root.

## Mục tiêu kiểm thử

- Xác nhận `root_path` bắt buộc phải là đường dẫn tuyệt đối.
- Xác nhận `server_name` là input tùy chọn và được validate về ký tự hợp lệ.
- Xác nhận plugin luôn tạo đủ 2 location block: ACME allow trước, hidden-file deny sau.
- Xác nhận thứ tự block không bị đảo vì điều này ảnh hưởng trực tiếp đến certbot renewal.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` lấy remediation của rule 2.5.3.
2. `read_child_ast_config()` lấy AST của file có vi phạm.
3. `_validate_user_inputs()` kiểm tra `root_path` và `server_name`.
4. `remediate()` tìm context mục tiêu, ưu tiên `server` block nếu `logical_context` yêu cầu.
5. `_upsert_location_block()` chèn deny block.
6. `_add_acme_exception_location()` chèn allow block trước deny block.
7. `child_ast_modified[file_path]["parsed"]` phải giữ nguyên cấu trúc server hợp lệ.

## Tiêu chí valid

- `root_path` phải bắt đầu bằng `/`.
- `server_name` rỗng là hợp lệ; nếu có thì chỉ nên chứa ký tự nginx-safe như chữ, số, `_`, `.`, `*`.
- Location `~ /\.well-known/acme-challenge/` phải cho phép `allow all;`.
- Location `~ /\.` phải `deny all;`.

## Tiêu chí invalid

- `root_path` rỗng hoặc không tuyệt đối là không hợp lệ.
- `server_name` chứa ký tự lạ là không hợp lệ.
- Chỉ có deny block mà thiếu ACME allow block là không hợp lệ.
- ACME block đặt sau deny block là không đạt yêu cầu.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` cho root path hợp lệ, root path sai, server_name sai.
- Kiểm tra guide detail nói rõ thứ tự ACME trước deny.

### Mutation correctness
- Thêm deny block và ACME block vào server block trống.
- Cập nhật server block đã có hidden-file rule.
- Giữ nguyên root_path trong block deny nếu user nhập hợp lệ.

### Safety / edge cases
- Nếu scan result trả về context ở parsed root, plugin phải không chèn sai vị trí.
- Nhiều server block: chỉ block mục tiêu được sửa.
- Nếu deny block đã có, ACME block vẫn phải đảm bảo đứng trước.

## Checklist xác minh

- `child_ast_modified` luôn chứa đủ 2 location block cho mỗi file được xử lý.
- Thứ tự của ACME và deny được giữ đúng.
- Không làm mất các directive khác trong server block.
- Diff thể hiện rõ 2 location block mới hoặc đã được upsert.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra `remedy_input_require` mô tả root_path và server_name.

### Nhóm B. Input validation (4-12)
4. `root_path=/var/www/html` hợp lệ.
5. `root_path=/srv/www/site` hợp lệ.
6. `root_path` rỗng, bị từ chối.
7. `root_path` không bắt đầu `/`, bị từ chối.
8. `server_name` rỗng, hợp lệ.
9. `server_name=_`, hợp lệ.
10. `server_name=example.com`, hợp lệ theo validator ký tự.
11. `server_name` chứa khoảng trắng, bị từ chối.
12. `server_name` chứa ký tự lạ, bị từ chối.

### Nhóm C. Mutation correctness - deny/ACME blocks (13-25)
13. Tạo deny block `location ~ /\\.`.
14. Tạo ACME block `location ~ /\\.well-known/acme-challenge/`.
15. ACME block đứng trước deny block.
16. Duy trì `allow all;` trong ACME block.
17. Duy trì `access_log on;` trong ACME block.
18. Duy trì `deny all;` trong deny block.
19. Duy trì `log_not_found off;` trong deny block.
20. Duy trì `root` trong deny block khi user cung cấp.
21. Upsert block khi deny đã tồn tại.
22. Upsert block khi ACME đã tồn tại.
23. Không tạo duplicate ACME block.
24. Không tạo duplicate deny block.
25. Cập nhật `server_name` ở parent level khi user nhập.

### Nhóm D. Ordering / placement (26-33)
26. Nếu deny đã có, ACME được insert trước vị trí deny.
27. Nếu deny chưa có, ACME được append và vẫn hợp lệ.
28. Nhiều server block, mutate đúng server mục tiêu.
29. Context trỏ root list, plugin không chèn sai root.
30. Logical context `server` được dùng làm fallback đúng.
31. File path normalize khác kiểu vẫn match đúng.
32. Violation nhiều file, mỗi file mutate độc lập.
33. Scan result có context lệch, plugin vẫn xử lý đúng target list.

### Nhóm E. Safety / no-op / diff (34-40)
34. Scan result rỗng, AST không đổi.
35. Nếu input invalid, `child_ast_modified` rỗng.
36. AST vẫn hợp lệ crossplane sau mutation.
37. Không làm mất directive khác trong server block.
38. Diff thể hiện đúng 2 location block và server_name nếu có.
39. Remediate lặp lại không làm thay đổi kết quả sai lệch.
40. Chỉ file có violation xuất hiện trong output modified.
