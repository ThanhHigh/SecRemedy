# Luồng Dữ Liệu Frontend — SecRemedy

## Tổng Quan Pipeline

```
[ USER ]
        │
        │ 1. SSH credentials (ip, port, user, pass) per server
        ▼
[ SERVER FORM — Streamlit ]
        │
        │ 2. User điền scanner params per server
        │    (authorized_ports, authorized_ips, strict_private, scan_server)
        ▼
[ SCANNER PARAM INPUT — Streamlit ]
        │
        │ 3. Ghi before_remediation.json
        ▼
[ PRE-CHECK UI ]
        │
        │ 4. nginx -t result (OK / FAIL + stderr)
        ▼
[ SCANNER ENGINE ]
        │ Đọc before_remediation.json → chạy scan → ghi scan_result JSON
        ▼
[ SCAN RESULTS UI — Streamlit ]
        │
        │ 5. Đọc scan_result JSON → hiển thị vi phạm + điểm
        ▼
[ REMEDIATION PARAM INPUT ] ─── (nếu có rule cần user input)
        │
        │ 6. User điền params → Streamlit ghi vào remediation config JSON
        ▼
[ REMEDIATION ENGINE ]
        │ Đọc scan_result JSON + remediation config JSON
        │ → chạy dry-run → ghi diff JSON
        ▼
[ DRY-RUN UI — Streamlit ]
        │
        │ 7. Đọc diff JSON → hiển thị Unified Diff
        ▼
[ APPROVE BUTTON ]
        │
        │ 8. User bấm Approve
        ▼
[ EXECUTE STATUS UI ]
        │
        │ 9. Engine push hardened config lên server
        ▼
[ TARGET SERVER ]
```

---

## Chi Tiết Từng Bước

### Bước 1 → 2: Server Form

| Thuộc tính | Mô tả |
|---|---|
| **Input** | SSH credentials per server: `ip`, `port`, `user`, `pass` |
| **Output** | Streamlit session state (chưa ghi file) |
| **Công nghệ** | Streamlit form |
| **Nhiệm vụ** | Thu thập thông tin kết nối SSH cho từng target server |

### Bước 2 → 3: Scanner Param Input

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Scanner params per server do user điền |
| **Output** | `tests/configs/before_remediation.json` |
| **Công nghệ** | Streamlit form → `json.dump()` |
| **Nhiệm vụ** | Thu thập params đánh giá CIS + ghi file contract cho Scanner Engine |

**Scanner params user phải điền:**

| Field | Kiểu | Mô tả |
|---|---|---|
| `authorized_ports` | `int[]` | Danh sách port hợp lệ — dùng cho rules đánh giá port |
| `authorized_ips` | `str[]` | Danh sách IP/CIDR hợp lệ — dùng cho rules đánh giá IP |
| `strict_private` | `bool` | Bật kiểm tra IP private nghiêm ngặt |
| `scan_server` | `bool` | `true` = scan server này; `false` = bỏ qua |

**Cấu trúc `before_remediation.json` sau khi ghi:**

```json
{
  "servers": [
    {
      "ip": "0.0.0.0",
      "port": 2220,
      "user": "root",
      "pass": "root",
      "strict_private": false,
      "input_path": "tmp/contracts/parsers_output/parser_output_2220.json",
      "output_path": "tmp/contracts/scan_result/scan_result_2220.json",
      "report_path": "tmp/contracts/scan_report/scan_report_2220.md",
      "authorized_ports": [80, 443, 8080, 8443, 9000],
      "authorized_ips": ["192.168.1.100", "10.20.30.0/24", "127.0.0.1", ...],
      "scan_server": true
    }
  ]
}
```

> `input_path`, `output_path`, `report_path` do Streamlit tự sinh theo `port` — user không cần điền.

### Bước 3 → 4: Pre-check UI

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Kết quả `nginx -t` từ engine (qua JSON hoặc stderr text) |
| **Output** | Hiển thị OK (tiếp tục) hoặc FAIL + stderr (dừng, báo lỗi) |
| **Nhiệm vụ** | Gate — chặn luồng sớm nếu config hiện tại đã lỗi cú pháp |

### Bước 4 → 5: Scanner Engine + Scan Results UI

| Thuộc tính | Mô tả |
|---|---|
| **Engine đọc** | `before_remediation.json` |
| **Engine ghi** | `scan_result_<port>.json` tại `output_path` |
| **Streamlit đọc** | `scan_result_<port>.json` |
| **Output UI** | Bảng vi phạm CIS (ID, mức độ, mô tả) + điểm tổng |
| **Nhiệm vụ** | Giao tiếp engine ↔ UI hoàn toàn qua file JSON |

### Bước 5 → 6: Remediation Param Input (Conditional)

| Thuộc tính | Mô tả |
|---|---|
| **Trigger** | Có ít nhất 1 rule cần user chọn hoặc nhập param fix |
| **Input** | Params user điền (dropdown / text field per rule) |
| **Output** | Streamlit ghi bổ sung params vào remediation config JSON |
| **Nhiệm vụ** | Thu thập tham số cho các rule không có fix mặc định chuẩn |

### Bước 6 → 7: Remediation Engine + Dry-Run UI

| Thuộc tính | Mô tả |
|---|---|
| **Engine đọc** | `scan_result_<port>.json` + remediation config JSON (params) |
| **Engine ghi** | `diff_<port>.json` (Unified Diff) |
| **Streamlit đọc** | `diff_<port>.json` |
| **Output UI** | Diff viewer (before/after per file, per rule) |
| **Nhiệm vụ** | Hiển thị thay đổi sẽ áp dụng — không ghi file thật |

### Bước 7 → 8: Approve Button

| Thuộc tính | Mô tả |
|---|---|
| **Trigger** | Diff hiển thị xong + params đã điền đủ |
| **Input** | User click Approve |
| **Output** | Gửi signal approve → engine chạy Execute |
| **Điều kiện** | Button disabled cho đến khi đủ điều kiện |

### Bước 8 → 9: Execute Status UI

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Kết quả push config từ engine (Success / Error JSON) |
| **Output** | Status alert + log (timestamp, file đã ghi, lỗi nếu có) |
| **Nhiệm vụ** | Thông báo kết quả cuối; hỗ trợ debug nếu Execute thất bại |

---

## Sơ Đồ Giao Tiếp Streamlit ↔ Engine

```
Streamlit (UI)                         Engine (Core)
     │                                       │
     │  [User: SSH creds + scanner params]   │
     │──── ghi before_remediation.json ─────▶│
     │                                       │──── SSH fetch + parse + scan
     │◀─── đọc scan_result JSON ─────────────│
     │     (scan_result_<port>.json)         │
     │                                       │
     │  [User: remediation params]           │
     │──── ghi remediation params JSON ─────▶│
     │                                       │──── dry-run + diff
     │◀─── đọc diff JSON ────────────────────│
     │     (diff_<port>.json)                │
     │                                       │
     │  [User: Approve]                      │
     │──── approve signal ──────────────────▶│
     │                                       │──── backup + push config
     │◀─── đọc execute result JSON ──────────│
```

---

## Nguyên Tắc UX An Toàn

- **JSON file = hợp đồng** — Streamlit + Engine chỉ giao tiếp qua file JSON, không gọi nhau trực tiếp
- **Luồng tuyến tính** — mỗi bước chỉ mở khóa khi bước trước ghi file JSON xong
- **Scan params bắt buộc trước scan** — `authorized_ports`, `authorized_ips` phải có trong config JSON trước khi scanner chạy
- **Dry-Run bắt buộc** — không thể Approve nếu chưa có diff JSON từ Remediation Engine
- **Approve bị khóa** — disabled cho đến khi diff hiển thị + params điền đủ
- **Pre-check gate** — `nginx -t` FAIL => dừng toàn bộ luồng
