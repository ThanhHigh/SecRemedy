# Tài liệu Kiểm thử: Remedy 252 (CIS Nginx Benchmark - Recommendation 2.5.2)

## Tổng quan

Recommendation 2.5.2 yêu cầu thay thế trang lỗi mặc định của NGINX bằng error page tùy biến. Plugin [Remediate252](../../../core/remedyEng/recommendations/remediate_252.py) là remediation có input bắt buộc, thực hiện thêm `error_page` directives và location block phục vụ page lỗi.

## Nguyên tắc kiểm thử độc lập

- Kiểm thử plugin bằng mock AST và mock remediation payload, không chạy scanner/parser.
- Dùng fixture tách bạch cho hai nhóm: `error_page` 404 và `error_page` 50x.
- Kiểm thử rõ hành vi override có điều kiện từ user input (`err_40x`, `err_50x`) so với `args` trong payload scan.
- Kiểm thử root-safety: context rơi vào parsed root list phải fallback hợp lệ hoặc skip an toàn.

## Mục tiêu kiểm thử

- Xác nhận input bắt buộc cho 40x, 50x và root 50x được validate đúng.
- Xác nhận URI error page phải là URI tuyệt đối bắt đầu bằng `/`.
- Xác nhận root path của location block phải là đường dẫn filesystem tuyệt đối và không chứa whitespace hay scheme.
- Xác nhận remediation thêm đúng `error_page` directives và location block có `internal`.

## Cách hoạt động dựa trên BaseRemedy

Luồng chính:

1. `read_child_scan_result()` lấy các remediation của rule 2.5.2 theo file.
2. `read_child_ast_config()` lấy AST của các file có vi phạm.
3. `_validate_user_inputs()` kiểm tra `err_40x`, `err_50x`, `root_50x`.
4. `remediate()` tìm target list từ context, fallback từ `http` sang `server` khi cần.
5. `_upsert_error_page()` thêm hoặc update `error_page` theo nhóm mã lỗi.
6. `_upsert_location_50x()` thêm location `= /50x.html` với `root` và `internal`.

## Tiêu chí valid

- `err_40x` và/hoặc `err_50x` phải là URI tuyệt đối như `/404.html` hoặc `/50x.html`.
- `root_50x` phải bắt đầu bằng `/` và là filesystem path hợp lệ.
- `error_page 404 /404.html;` và `error_page 500 502 503 504 /50x.html;` là cấu hình hợp lệ.
- Location phục vụ error page phải có `internal;`.

## Tiêu chí invalid

- URI bắt đầu bằng `./` là không hợp lệ.
- URI không bắt đầu bằng `/` là không hợp lệ.
- `root_50x` có chứa whitespace hoặc scheme như `http://` là không hợp lệ.
- Không có ít nhất một trong hai error page path thì không được remediation.

## Phạm vi test cần có

### Metadata / contract
- Kiểm tra `has_input == True`.
- Kiểm tra `_validate_user_inputs()` với input thiếu, URI sai, root sai.
- Kiểm tra `remedy_input_require` phản ánh đúng 3 đầu vào.

### Mutation correctness
- Chèn `error_page` cho 404.
- Chèn `error_page` cho 50x.
- Tạo location `= /50x.html` với `root` và `internal`.
- Cập nhật cùng rule khi `error_page` đã tồn tại.

### Safety / edge cases
- Context trỏ root list phải fallback sang `http` hoặc `server`.
- Chỉ file có vi phạm mới được mutate.
- Nếu `root_50x` rỗng thì chỉ thêm error_page, không thêm location block.

## Checklist xác minh

- `child_ast_modified` giữ nguyên AST hợp lệ sau mutation.
- `error_page` directives đúng nhóm mã lỗi và đúng URI.
- Location 50x có `internal` và `root` đúng.
- Không chèn `error_page` vào parsed root list.

## Ma trận testcase chi tiết (~40)

### Nhóm A. Metadata / contract (1-3)
1. Kiểm tra kế thừa `BaseRemedy`.
2. Kiểm tra `has_input == True`.
3. Kiểm tra `remedy_input_require` có đủ 3 input.

### Nhóm B. Input validation - error page URI (4-13)
4. `err_40x=/404.html` hợp lệ.
5. `err_50x=/50x.html` hợp lệ.
6. Cả hai URI đều hợp lệ.
7. URI rỗng cho 40x, 50x hợp lệ.
8. URI rỗng cho 50x, 40x hợp lệ.
9. Cả hai URI rỗng, bị từ chối.
10. URI bắt đầu bằng `./` cho 40x, bị từ chối.
11. URI bắt đầu bằng `./` cho 50x, bị từ chối.
12. URI không bắt đầu bằng `/`, bị từ chối.
13. URI chứa `://`, bị từ chối.

### Nhóm C. Input validation - root path (14-19)
14. `root_50x=/var/www/html/errors` hợp lệ.
15. `root_50x=/srv/www/errors` hợp lệ.
16. `root_50x` rỗng, chỉ tạo error_page.
17. `root_50x` không bắt đầu `/`, bị từ chối.
18. `root_50x` chứa khoảng trắng, bị từ chối.
19. `root_50x` chứa scheme `http://`, bị từ chối.

### Nhóm D. Mutation correctness (20-30)
20. Thêm `error_page 404 /404.html;`.
21. Thêm `error_page 500 502 503 504 /50x.html;`.
22. Add cả 2 error_page directives trong cùng file.
23. Upsert `error_page` 404 nếu đã tồn tại.
24. Upsert `error_page` 50x nếu đã tồn tại.
25. Tạo location `= /50x.html` mới.
26. location `= /50x.html` có `root` đúng.
27. location `= /50x.html` có `internal;`.
28. location 50x không bị duplicate khi gọi lại.
29. Khi user đổi `root_50x`, `root` trong location được cập nhật.
30. Khi `err_50x` đổi, location args đổi tương ứng.

### Nhóm E. Safety / context / no-op (31-40)
31. Context rỗng, plugin fallback sang `http` hoặc `server`.
32. Context trỏ directive khác, không chèn sai root.
33. AST có nhiều server block, mutate đúng block target.
34. File path normalize khác kiểu vẫn match đúng.
35. Scan result rỗng thì AST không đổi.
36. Chỉ file có violation mới xuất hiện trong `child_ast_modified`.
37. Khi chỉ 40x hợp lệ, plugin vẫn tạo đúng 40x error_page.
38. Khi chỉ 50x hợp lệ, plugin vẫn tạo đúng 50x error_page.
39. Không chèn location 50x nếu root_50x rỗng.
40. Diff thể hiện chính xác add/upsert mà không phá cấu trúc block.
