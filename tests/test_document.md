# test_document cho SecRemedy

Tài liệu này là checklist trạng thái cho bộ test integration của dự án SecRemedy.

Mục đích:

- nhìn vào là biết port nào đã làm xong
- biết file test nằm ở folder nào trong `tests/integration`
- biết cấu hình đó đang lược bỏ / vi phạm luật CIS nào
- tách rõ case đã có port và case còn treo
- bỏ qua cột tác giả và thông tin phụ, vì chỉ là metadata

## Quy ước đọc

- `[x]` = đã có file test trong `tests/integration`
- `[ ]` = chưa làm xong hoặc chưa chốt file
- `x241` = luật 2.4.1
- `x242` = luật 2.4.2
- `x251` = luật 2.5.1
- `x252` = luật 2.5.2
- `x253` = luật 2.5.3
- `x254` = luật 2.5.4
- `x32` = luật 3.2
- `x34` = luật 3.4
- `x411` = luật 4.1.1
- `x511` = luật 5.1.1
- `x531` = luật 5.3.1
- `x532` = luật 5.3.2

## Checklist theo folder

### `tests/integration/zero-comply`

- [x] `nginx.conf` nền sạch để đối chiếu
- [x] `mime.types` đi kèm bộ nền chuẩn
- [x] `conf.d/` đi kèm bộ nền chuẩn
- [x] Mục đích: không gắn ý đồ vi phạm luật nào, dùng làm baseline

### `tests/integration/0_to_1_uncomply`

- [x] `nginx_raw_2230` nằm ở `tests/integration/0_to_1_uncomply/nginx_raw_2230/` — case chỉ 0 đến 1 luật sai; sheet không tách rõ luật nào
- [x] `nginx_raw_2240` nằm ở `tests/integration/0_to_1_uncomply/nginx_raw_2240/` — case chỉ 0 đến 1 luật sai; sheet không tách rõ luật nào
- [x] `nginx_raw_2250` nằm ở `tests/integration/0_to_1_uncomply/nginx_raw_2250/` — case chỉ 0 đến 1 luật sai; sheet không tách rõ luật nào
- [x] `nginx_raw_2260` nằm ở `tests/integration/0_to_1_uncomply/nginx_raw_2260/` — case chỉ 0 đến 1 luật sai; sheet không tách rõ luật nào
- [x] `nginx_raw_2270` nằm ở `tests/integration/0_to_1_uncomply/nginx_raw_2270/` — case chỉ 0 đến 1 luật sai; sheet không tách rõ luật nào

### `tests/integration/1_to_3_uncomply`

- [x] `nginx_raw_2231` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2231/` — đã làm xong; lược bỏ luật 3.2 và 3.4
- [x] `nginx_raw_2234` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2234/` — đã làm xong; lược bỏ luật 2.5.3 và 2.5.4
- [x] `nginx_raw_2241` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2241/` — đã làm xong; lược bỏ luật 3.2 và 3.4
- [x] `nginx_raw_2244` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2244/` — đã làm xong; lược bỏ luật 2.5.3 và 2.5.4
- [x] `nginx_raw_2251` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2251/` — đã làm xong; lược bỏ luật 3.2 và 3.4
- [x] `nginx_raw_2254` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2254/` — đã làm xong; lược bỏ luật 2.5.3 và 2.5.4
- [x] `nginx_raw_2261` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2261/` — đã làm xong; lược bỏ luật 3.2 và 3.4
- [x] `nginx_raw_2264` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2264/` — đã làm xong; lược bỏ luật 2.5.3 và 2.5.4
- [x] `nginx_raw_2271` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2271/` — đã làm xong; lược bỏ luật 3.2 và 3.4
- [x] `nginx_raw_2274` nằm ở `tests/integration/1_to_3_uncomply/nginx_raw_2274/` — đã làm xong; lược bỏ luật 2.5.3 và 2.5.4

Các case chưa chốt port nhưng dự kiến cũng vào folder này:

- [ ] `nginx_raw_(dòng 7)` — dự kiến `tests/integration/1_to_3_uncomply/` — lược bỏ luật 2.5.3 và 2.5.4
- [ ] `nginx_raw_(dòng 17)` — dự kiến `tests/integration/1_to_3_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 5.1.1
- [ ] `nginx_raw_(dòng 27)` — dự kiến `tests/integration/1_to_3_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 5.1.1
- [ ] `nginx_raw_(dòng 37)` — dự kiến `tests/integration/1_to_3_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 5.1.1
- [ ] `nginx_raw_(dòng 47)` — dự kiến `tests/integration/1_to_3_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 5.1.1

### `tests/integration/3_to_4_uncomply`

- [x] `nginx_raw_2232` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2232/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.1
- [x] `nginx_raw_2233` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2233/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.2
- [x] `nginx_raw_2242` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2242/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.1, 2.5.1
- [x] `nginx_raw_2243` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2243/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.2
- [x] `nginx_raw_2252` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2252/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.1
- [x] `nginx_raw_2253` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2253/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.2
- [x] `nginx_raw_2262` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2262/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.1, 2.5.1
- [x] `nginx_raw_2263` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2263/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.2
- [x] `nginx_raw_2272` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2272/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.1, 2.5.1
- [x] `nginx_raw_2273` nằm ở `tests/integration/3_to_4_uncomply/nginx_raw_2273/` — đã làm xong; lược bỏ luật 3.2, 3.4, 2.4.2

Các case chưa chốt port nhưng dự kiến vào folder này:

- [ ] `nginx_raw_2235` — dự kiến `tests/integration/3_to_4_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1
- [ ] `nginx_raw_(dòng 16)` — dự kiến `tests/integration/3_to_4_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1
- [ ] `nginx_raw_(dòng 26)` — dự kiến `tests/integration/3_to_4_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1
- [ ] `nginx_raw_(dòng 36)` — dự kiến `tests/integration/3_to_4_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1
- [ ] `nginx_raw_(dòng 46)` — dự kiến `tests/integration/3_to_4_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1

### `tests/integration/10_to_12_uncomply`

- [x] `nginx_raw_2239` nằm ở `tests/integration/10_to_12_uncomply/nginx_raw_2239/` — đã làm xong; sheet ghi `lỗi hết`, tức là case có 10 đến 12 luật sai, chưa tách riêng rule nào
- [x] `nginx_raw_2249` nằm ở `tests/integration/10_to_12_uncomply/nginx_raw_2249/` — đã làm xong; sheet ghi `lỗi hết`, tức là case có 10 đến 12 luật sai, chưa tách riêng rule nào
- [x] `nginx_raw_2259` nằm ở `tests/integration/10_to_12_uncomply/nginx_raw_2259/` — đã làm xong; sheet ghi `lỗi hết`, tức là case có 10 đến 12 luật sai, chưa tách riêng rule nào
- [x] `nginx_raw_2269` nằm ở `tests/integration/10_to_12_uncomply/nginx_raw_2269/` — đã làm xong; sheet ghi `lỗi hết`, tức là case có 10 đến 12 luật sai, chưa tách riêng rule nào
- [x] `nginx_raw_2279` nằm ở `tests/integration/10_to_12_uncomply/nginx_raw_2279/` — đã làm xong; sheet ghi `lỗi hết`, tức là case có 10 đến 12 luật sai, chưa tách riêng rule nào

### `tests/integration/5_to_7_uncomply`

- [ ] `nginx_raw_(dòng 8)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 3.2, 3.4, 2.4.2, 5.3.2, 5.3.1
- [ ] `nginx_raw_(dòng 9)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 5.1.1, 2.5.2, 2.5.1
- [ ] `nginx_raw_(dòng 18)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 3.2, 3.4, 2.4.2, 5.3.2, 5.3.1
- [ ] `nginx_raw_(dòng 19)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1, 2.4.2, 3.4
- [ ] `nginx_raw_(dòng 28)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 3.2, 3.4, 2.4.2, 5.3.2, 5.3.1
- [ ] `nginx_raw_(dòng 29)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 5.1.1, 2.5.2, 2.5.1
- [ ] `nginx_raw_(dòng 38)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 3.2, 3.4, 2.4.2, 5.3.2, 5.3.1
- [ ] `nginx_raw_(dòng 39)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1, 2.4.2, 3.4
- [ ] `nginx_raw_(dòng 48)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 3.2, 3.4, 2.4.2, 5.3.2, 5.3.1
- [ ] `nginx_raw_(dòng 49)` — dự kiến `tests/integration/5_to_7_uncomply/` — lược bỏ luật 2.5.3, 2.5.4, 4.1.1, 5.3.1, 2.4.2, 3.4

## Tóm tắt nhanh

- Bộ test đã chia theo nhóm folder rõ ràng
- Port có ghi trong sheet thì coi là đã làm xong
- Port không có trong folder tương ứng thì coi là chưa chốt xong hoặc còn treo
- Dòng `lỗi hết` nghĩa là case có 10 đến 12 luật sai, chưa tách rule riêng trong sheet
- Dòng gần sạch nghĩa là case chỉ 0 đến 1 luật sai, chỉ dùng để đối chiếu và tránh bắn nhầm

## Ghi chú cho partner và agent

Nếu muốn mở rộng thêm, chỉ cần giữ cùng format:

- `[x]` hoặc `[ ]`
- tên `nginx_raw_<port>`
- đường dẫn đầy đủ trong `tests/integration/...`
- danh sách luật đã lược bỏ theo ký hiệu `x...`

Cách này giúp đọc nhanh, map được file, và biết ngay case đó đã hoàn tất hay chưa.
