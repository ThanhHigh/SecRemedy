# Luồng Dữ Liệu Tổng Quan — SecRemedy

## Tầng 1: Frontend — Streamlit UI

| Dashboard UI | Remediation UI |
|---|---|
| Hiển thị Score | Nút **Dry-Run** → Hiển thị Diff |
| Danh sách luật CIS vi phạm | Xem Diff → Nút **Approve** mở khóa |

**Luồng tín hiệu:**
- UI → Backend: `Click Scan` / `Dry-Run` / `Approve`
- Backend → UI: `JSON` / `Diff + Status`

---

## Tầng 2: Backend API — FastAPI

```
POST /scan
POST /dry-run
POST /approve
```

Mỗi endpoint phân nhánh xuống 3 luồng độc lập:

| Luồng | Mô tả |
|---|---|
| **Scan flow** | Quét cấu hình nginx |
| **Dry-Run flow** | Tạo diff, không ghi file |
| **Execute flow** | Áp dụng thay đổi thực tế |

### Pre-check: `nginx -t`

Trước khi scan, backend SSH vào server và chạy `nginx -t`:

- **FAIL** → Trả lỗi về UI (hiển thị stderr output), dừng luồng
- **OK** → Tiếp tục scan

---

## Tầng 3: Core Engines

### Scanner Engine

```
SSH Fetcher
  └─ Kéo /etc/nginx/ về local
       └─ Crossplane Wrapper
            └─ Parse text → ast_dict
                 └─ Rules Evaluation
                      └─ Duyệt AST qua BaseRule
                           └─ Scanner & DB
                                └─ Tính điểm, lưu SQLite
```

### Remediation Engine

```
AST Locator
  └─ Tìm vị trí sửa trong AST (theo scan_result.json)
       └─ AST Injector
            └─ Tiêm code → mod_ast
                 └─ Crossplane Builder
                      └─ Build AST → fixed.conf
                           └─ Diff Generator
                                └─ So sánh → Unified Diff
```

### Safe Pipeline

```
SSH Backup
  └─ cp -R /etc/nginx/ (backup toàn bộ)
       └─ Executor
            └─ Push hardened config lên /etc/nginx/* server
```

---

## Tầng 4: Infrastructure

### SQLite Database

| Bảng | Mục đích |
|---|---|
| `Servers` | Thông tin target server |
| `ScanResults` | Kết quả quét CIS |
| `Remediations` | Trạng thái remediation (pending / applied / failed) |

---

## Sơ đồ Tổng Quan

```
[ Streamlit UI ]
      |
      ▼
[ FastAPI: /scan  /dry-run  /approve ]
      |              |              |
      ▼              ▼              ▼
[ nginx -t PRE-CHECK ]
      |
      ▼
┌─────────────────┬──────────────────────┬─────────────────┐
│ Scanner Engine  │ Remediation Engine   │ Safe Pipeline   │
│                 │                      │                 │
│ SSH Fetch       │ AST Locate           │ SSH Backup      │
│ Crossplane Parse│ AST Inject           │ Push Config     │
│ Rules Evaluate  │ Build fixed.conf     │                 │
│ Score + SQLite  │ Unified Diff         │                 │
└────────┬────────┴──────────────────────┴─────────────────┘
         │
         ▼
[ SQLite DB: Servers | ScanResults | Remediations ]
```
