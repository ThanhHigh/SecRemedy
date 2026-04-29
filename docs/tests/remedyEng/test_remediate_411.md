# Tài liệu Kiểm thử: Remedy 411 (CIS Nginx Benchmark - Recommendation 4.1.1)

## Tổng quan

Recommendation 4.1.1 yêu cầu redirect HTTP sang HTTPS. Plugin [Remediate411](../../../core/remedyEng/recommendations/remediate_411.py) là remediation có input, tạo hoặc cập nhật `return` directive với mã redirect và target HTTPS.

## Nguyên tắc kiểm thử độc lập

- Chỉ test mutation plugin từ mock remediation payload.
- Không phụ thuộc scanner/parser runtime.
- Bắt buộc có test root-context guard: không chèn `return` vào parsed root list.
- Bắt buộc có test fallback context vào `server` block khi context từ payload không trực tiếp insert được.

## Mục tiêu kiểm thử

- Xác nhận redirect code chỉ nhận `301`, `302`, hoặc `307`.
- Xác nhận target phải bắt đầu bằng `https://` và chứa `$request_uri`.
- Xác nhận plugin chèn `return` đúng vào server block phù hợp, không chèn ở parsed root.
- Xác nhận `return` được add hoặc replace đúng khi action thay đổi.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` gom remediation của rule 4.1.1 theo file.
2. `read_child_ast_config()` lấy AST của file có violation.
3. `_validate_user_inputs()` chuẩn hóa defaults và kiểm tra target.
4. `remediate()` xác định target context bằng `_relative_context()` và fallback sang server block khi cần.
5. `_upsert_in_block()` thêm `return` vào block list hoặc update args nếu directive đã tồn tại.

## Tiêu chí valid

- `301`, `302`, `307` là redirect code hợp lệ.
- Target như `https://$host$request_uri` là hợp lệ.
- Có thể dùng server block đang listen 80 để đặt redirect.

## Tiêu chí invalid

- Code ngoài tập `301/302/307` là không hợp lệ.
- Target không bắt đầu bằng `https://` là không hợp lệ.
- Target thiếu `$request_uri` là không hợp lệ vì mất path/query gốc.
- Chèn `return` ở parsed root là sai.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` với code sai, target sai, target thiếu `$request_uri`.
- Kiểm tra defaults khi input rỗng.

### Mutation correctness
- Add `return 301 https://$host$request_uri;` vào server block.
- Replace `return` hiện có bằng code/target mới.
- Tự động fallback sang server block khi scan context không đủ sâu.

### Safety / edge cases
- Context rỗng không được đưa directive vào root.
- Multi-file config chỉ sửa file bị violation.
- Nhiều server block thì target block phải hợp lý theo logic hiện tại.

## Checklist xác minh

- `child_ast_modified` có `return` directive đúng args.
- Redirect target luôn còn `$request_uri`.
- Không tạo block mới không cần thiết.
- Diff phản ánh redirect rule rõ ràng và không làm gãy cấu trúc block.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra guide detail mô tả redirect HTTP→HTTPS.

### Nhóm B. Input validation (4-12)
4. Code `301` hợp lệ.
5. Code `302` hợp lệ.
6. Code `307` hợp lệ.
7. Code rỗng, auto default `301`.
8. Code không nằm trong tập cho phép, bị từ chối.
9. Target `https://$host$request_uri` hợp lệ.
10. Target `https://example.com$request_uri` hợp lệ.
11. Target không bắt đầu `https://`, bị từ chối.
12. Target thiếu `$request_uri`, bị từ chối.

### Nhóm C. Mutation correctness (13-25)
13. Add `return 301 https://$host$request_uri;`.
14. Add `return 302 https://$host$request_uri;`.
15. Add `return 307 https://$host$request_uri;`.
16. Replace `return` hiện có.
17. Update args khi scan result đã có `return` directive.
18. Target server block listen 80 được chọn để chèn return.
19. Target block hiện có `return` và node được cập nhật.
20. Target list block nhận directive mới đúng vị trí.
21. Không tạo duplicate return directive khi đã có sẵn.
22. Fallback sang server block khi context lệch.
23. Giữ `server_name` hiện có trong block.
24. Giữ directive khác trong block.
25. Chèn return trong block server đúng scope.

### Nhóm D. Context / safety (26-34)
26. Context rỗng không chèn sai root.
27. Context là directive object, plugin vẫn xử lý đúng.
28. Nhiều server block, mutate đúng block target.
29. File path normalize khác kiểu vẫn match đúng.
30. Scan result cho rule khác không đổi AST.
31. `child_ast_modified` chỉ có file vi phạm.
32. AST root list không bị thêm return sai chỗ.
33. Remediate lặp lại không làm thay đổi sai.
34. Deep copy AST không alias input.

### Nhóm E. Regression / edge (35-40)
35. Scan result rỗng, AST không đổi.
36. Input thiếu một phần, plugin dùng default an toàn.
37. Redirect code 301 vẫn giữ nguyên target đúng.
38. Target có query string vẫn giữ nguyên `$request_uri`.
39. Diff chỉ thể hiện return directive.
40. AST sau sửa vẫn giữ cấu trúc crossplane hợp lệ.
