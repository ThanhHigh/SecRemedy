# Remediation Engine — Data Flow

**Input:** `scan_result.json` (từ Scanner Engine)  
**Output:** Hardened Nginx config đã push lên target server

---

## Pipeline Tổng Quan

```
[ tmp/contracts/scan_result/scan_result.json ]
        │
        │  uncompliance[] { remediations[] }
        │  remediations[i] = { action, directive, args, line, logical_context, exact_path }
        ▼
[ STEP 1: SCAN RESULT READER ]
        │
        │  exact_path = ["config", 0, "parsed", 6, "block", ...]
        ▼
[ STEP 2: AST LOCATOR ]
        │
        │  node ref trong AST dict (in-memory)
        ▼
[ STEP 3: AST INJECTOR ]
        │
        │  modified AST (in-memory dict)
        ▼
[ STEP 4: CROSSPLANE BUILDER ]
        │
        │  tmp/hardened_configs/<port>_hardened.conf (text)
        ▼
[ STEP 5: DIFF GENERATOR ]
        │
        │  unified_diff (text)
        ▼
[ FRONTEND UI — Dry-Run Review ]
        │
        │  User nhấn "Approve"
        ▼
[ APPROVE GATE ]
        │
        │  Gate passed
        ▼
[ STEP 6: EXECUTOR ]
        │
        │  Hardened Nginx config trên server
        ▼
[ TARGET SERVER — /etc/nginx/* đã hardened ]
```

---

## Chi Tiết Từng Bước

### Step 1: Scan Result Reader

| Thuộc tính | Mô tả |
|---|---|
| **Input** | `tmp/contracts/scan_result/<port>_scan_result.json` |
| **Nhiệm vụ** | Load file, duyệt `uncompliance[]`, xếp hàng `remediations` |
| **Output** | Queue các remediation item cần xử lý |

### Step 2: AST Locator

| Thuộc tính | Mô tả |
|---|---|
| **Input** | `tmp/contracts/parsers_output/<port>_ast.json` + `exact_path` |
| **Nhiệm vụ** | Đi theo `exact_path` trong AST, trỏ đến node cần sửa |
| **Output** | Node reference trong AST dict (in-memory) |

`exact_path` ví dụ:
```json
["config", 0, "parsed", 6, "block", 2]
```

### Step 3: AST Injector

| Action | Hành động |
|---|---|
| `add` | Chèn directive mới vào AST tại node |
| `replace` | Xóa directive cũ, chèn directive mới vào AST tại node |
| `delete` | Xóa node khỏi AST |

> Các directive đều có thể có block con đi kèm.

**Output:** Modified AST (in-memory dict)

### Step 4: Crossplane Builder

| Thuộc tính | Mô tả |
|---|---|
| **Công nghệ** | `crossplane.build()` |
| **Input** | Modified AST dict |
| **Output** | `.conf` text → lưu vào `tmp/hardened_configs/<port>_hardened.conf` |

### Step 5: Diff Generator

| Thuộc tính | Mô tả |
|---|---|
| **Công nghệ** | `difflib.unified_diff()` |
| **So sánh** | `original.conf` vs `hardened.conf` |
| **Output** | Unified Diff text → gửi lên Frontend UI |

### Approve Gate

```
Dry-Run xong → Hiển thị diff trên UI
User review từng thay đổi
User nhấn "Approve" → Gate mở
```

Gate chỉ mở khi **User chủ động nhấn Approve** — không tự động.

### Step 6: Executor

| Thuộc tính | Mô tả |
|---|---|
| **Trigger** | Approve Gate passed |
| **Backup** | `cp -R /etc/nginx/ /etc/nginx.bak/` trước khi ghi đè |
| **Push** | SFTP đẩy hardened config lên `/etc/nginx/*` |
| **Note** | Không chạy `nginx -s reload` (nằm ngoài scope Executor) |

---

## Trạng Thái DB (SQLite — Remediation Table)

| Trạng thái | Điều kiện |
|---|---|
| `pending` | Dry-Run xong, chờ Approve |
| `approved` | User nhấn Approve |
| `applied` | Executor push thành công |
| `failed` | SSH lỗi hoặc SFTP lỗi |

---

## File I/O Mapping

| Vai trò | Đường dẫn |
|---|---|
| **INPUT** | `tmp/contracts/scan_result/<port>_scan_result.json` |
| **INPUT** | `tmp/contracts/parsers_output/<port>_ast.json` |
| **WORK** | `tmp/hardened_configs/<port>_hardened.conf` |
| **OUTPUT** | `/etc/nginx/*` trên target server |
| **BACKUP** | `/etc/nginx.bak/*` trên target server |
