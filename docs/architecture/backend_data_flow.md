# Luồng Dữ Liệu Backend — SecRemedy

## Tổng Quan Pipeline

```
[ TARGET SERVERS ]
        │
        │ 1. Raw Nginx Config Files (/etc/nginx/*)
        ▼
[ FETCHER ]
        │
        │ 2. Raw Text Files (Local /tmp/)
        ▼
[ PARSER ]
        │
        │ 3. Parsed AST (JSON)
        ▼
[ CIS RULES EVALUATOR ]
        │
        │ 4. scan_results (JSON)
        ▼
[ LOCATOR & INJECTOR ]
        │
        │ 5. fixed AST (JSON)
        ▼
[ BUILDER ]
        │
        │ 6. Hardened Nginx Config Files (Text)
        ▼
[ DIFF GENERATOR ] ──────────────────────── [ BACKUP ]
        │                                        │
        │ 7. diffs (JSON / Unified Diff)         │ 8. Backup OK
        ▼                                        ▼
[ FRONTEND UI ]                          [ EXECUTOR ]
  Hiển thị Dry-Run                              │
  User Approve ───────────────────────────────▶ │
                                                │ 9. Push hardened config (/etc/nginx/*)
                                                ▼
                                        [ TARGET SERVERS ]
```

---

## Chi Tiết Từng Bước

### Bước 1 → 2: Fetcher

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Target server SSH credentials |
| **Output** | Raw text files lưu tại `/tmp/` local |
| **Công nghệ** | `paramiko` (SSH) |
| **Nhiệm vụ** | Kéo toàn bộ `/etc/nginx/*` về máy local |

### Bước 2 → 3: Parser

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Raw text files (`/tmp/`) |
| **Output** | Parsed AST dạng JSON |
| **Công nghệ** | `crossplane` (đệ quy theo `include`) |
| **Nhiệm vụ** | Chuyển config text → cấu trúc AST có thể xử lý |

### Bước 3 → 4: CIS Rules Evaluator

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Parsed AST (JSON) |
| **Output** | `scan_results` (JSON) — danh sách vi phạm + điểm |
| **Công nghệ** | Custom `BaseRule` engine |
| **Nhiệm vụ** | Đối chiếu AST với tập luật CIS Benchmark |

### Bước 4 → 5: Locator & Injector

| Thuộc tính | Mô tả |
|---|---|
| **Input** | `scan_results` (JSON) + AST gốc |
| **Output** | `fixed AST` (JSON) — đã tiêm cấu hình chuẩn |
| **Nhiệm vụ** | Tìm đúng vị trí vi phạm trong AST, tiêm config fix vào RAM |

### Bước 5 → 6: Builder

| Thuộc tính | Mô tả |
|---|---|
| **Input** | `fixed AST` (JSON) |
| **Output** | Hardened Nginx config files (text) |
| **Công nghệ** | `crossplane` (reverse build) |
| **Nhiệm vụ** | Dịch ngược AST đã sửa → file config text |

### Bước 6 → 7: Diff Generator

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Config gốc + config đã hardened |
| **Output** | Unified Diff (JSON hoặc text) |
| **Công nghệ** | `difflib` |
| **Nhiệm vụ** | Tạo diff để hiển thị trên UI (Dry-Run) |

### Song song — Backup

| Thuộc tính | Mô tả |
|---|---|
| **Trigger** | Ngay khi có lệnh Approve từ User |
| **Hành động** | `cp -R /etc/nginx/` trên server trước khi ghi đè |
| **Mục đích** | An toàn rollback nếu xảy ra lỗi |

### Bước 8 → 9: Executor

| Thuộc tính | Mô tả |
|---|---|
| **Input** | Hardened config files + Backup OK signal |
| **Trigger** | **Chỉ chạy khi User bấm Approve** |
| **Output** | Config được đẩy lên `/etc/nginx/*` server |
| **Công nghệ** | `paramiko` (SSH push) |

---

## Nguyên Tắc An Toàn

- **Dry-Run trước** — diff hiển thị UI, không ghi file
- **Backup bắt buộc** — `cp -R` trước mọi thao tác ghi
- **Approve mới Execute** — Executor bị khóa cho đến khi User xác nhận
- **`nginx -t` pre-check** — validate syntax trước khi bắt đầu pipeline
