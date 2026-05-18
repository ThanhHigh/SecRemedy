# Remediation Engine — Data Flow

**Input:** `tmp/contracts/scan_result/scan_result_{port}.json` (từ Scanner Engine)  
**Output:** Hardened Nginx config đã push lên target server

---

## Pipeline Tổng Quan

```
[ tmp/contracts/scan_result/scan_result_{port}.json ]
        │
        │  recommendations[] { uncompliances[] { remediations[] } }
        │  remediations[i] = { file, action, directive, args, block, line, logical_context, exact_path }
        ▼
[ STEP 1: SCAN RESULT READER ]
        │
        │  RemediationItem[] — sorted DESC by exact_path
        ▼
[ STEP 2: AST LOCATOR + STEP 3: AST INJECTOR ]
        │
        │  (deep copy original AST → modify in-place per item)
        │  skipped[] items logged nếu path invalid
        ▼
[ STEP 4: CONFIG BUILDER ]
        │
        │  tmp/hardened_configs/{port}/<relative_path>.conf (text)
        │  tmp/contracts/mod_asts/mod_ast_{port}.json (audit snapshot)
        ▼
[ STEP 5: DIFF GENERATOR ]
        │
        │  Dict[remote_path → unified_diff_text]
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
        │  SSH backup + SFTP push
        ▼
[ TARGET SERVER — /etc/nginx/* đã hardened ]
```

---

## Chi Tiết Từng Bước

### Step 1: Scan Result Reader

| Thuộc tính | Mô tả |
|---|---|
| **Class** | `ScanResultReader` — `core/remedyEng/reader.py` |
| **Input** | `tmp/contracts/scan_result/scan_result_{port}.json` |
| **Filter** | Chỉ lấy `recommendations[]` có `status == "fail"` |
| **Flatten** | `uncompliances[] → remediations[]` |
| **Output** | `RemediationItem[]` — sorted DESC by `exact_path` (tránh index-shift khi inject) |

`RemediationItem` fields:
```python
file: str              # Target config file (remote path)
action: str            # "add" | "replace" | "delete"
directive: str         # Nginx directive name
args: list[str]        # Argument list
block: list[dict]      # Nested block directives
line: int              # Original line number
logical_context: list  # Breadcrumb path, e.g. ["http", "server"]
exact_path: list       # AST navigation path, e.g. ["config", 0, "parsed", 6, "block", 2]
```

---

### Step 2: AST Locator

| Thuộc tính | Mô tả |
|---|---|
| **Class** | `ASTLocator` — `core/remedyEng/locator.py` |
| **Input** | `tmp/contracts/parsers_output/parser_output_{port}.json` + `exact_path` |
| **Output** | `(parent_list, index | None)` — trỏ vào vị trí cần sửa |

- `exact_path` kết thúc bằng `int` → trả `(parent_list, index)` (replace/delete)
- `exact_path` kết thúc bằng `str` → trả `(parent_list, None)` (append mode)

---

### Step 3: AST Injector

| Thuộc tính | Mô tả |
|---|---|
| **Class** | `ASTInjector` — `core/remedyEng/injector.py` |
| **Input** | AST dict (deep copy) + `RemediationItem` |
| **Output** | Modified AST (in-place) |

| Action | Hành động |
|---|---|
| `add` | Chèn directive mới vào parent list tại index hoặc append |
| `replace` | Xóa node cũ, chèn directive mới tại cùng vị trí |
| `delete` | Xóa node khỏi parent list |

> Exceptions (KeyError, IndexError, TypeError, ValueError) → item bị skip, ghi log, batch tiếp tục.

**Sites-enabled rewrite:** Các path chứa `sites-enabled` được rewrite → `sites-available` (nginx convention — sites-enabled là symlink, file thật ở sites-available).

---

### Step 4: Config Builder

| Thuộc tính | Mô tả |
|---|---|
| **Class** | `ConfigBuilder` — `core/remedyEng/builder.py` |
| **Công nghệ** | `crossplane.build()` |
| **Input** | Modified AST dict + `strip_prefix` (e.g., `/etc/nginx`) |
| **Output** | `.conf` files → `tmp/hardened_configs/{port}/<relative_path>/` |
| **Audit** | Snapshot AST → `tmp/contracts/mod_asts/mod_ast_{port}.json` |
| **Marker** | `tmp/hardened_configs/{port}/.remote_base` — lưu common parent dir (e.g., `/etc/nginx`) |

---

### Step 5: Diff Generator

| Thuộc tính | Mô tả |
|---|---|
| **Class** | `DiffGenerator` — `core/remedyEng/diff_generator.py` |
| **Công nghệ** | `difflib.unified_diff()` |
| **Input** | Original AST + Hardened AST (cả hai build bằng crossplane) |
| **Output** | `Dict[remote_path → unified_diff_text]` + merged string |

`dry_run()` trả về:
```python
{
    "diff": str,                   # Merged unified diff
    "file_diffs": dict,            # Per-file diffs keyed by remote path
    "hardened_dir": str,           # tmp/hardened_configs/{port}/
    "output_files": list[str],     # Paths đã ghi
    "status": "pending" | "no_changes",
    "skipped": list                # Items failed to apply + lý do
}
```

---

### Approve Gate

```
Dry-Run xong → Hiển thị diff trên UI
User review từng thay đổi
User nhấn "Approve" → Gate mở
```

Gate chỉ mở khi **User chủ động nhấn Approve** — không tự động.

Optional: `approved_files: list[str]` — whitelist remote paths cần push (nếu không truyền → push tất cả).

---

### Step 6: Executor

| Thuộc tính | Mô tả |
|---|---|
| **Class** | `RemoteExecutor` — `core/remedyEng/executor.py` |
| **Trigger** | Approve Gate passed |
| **Backup** | SSH exec: `cp -R /etc/nginx/ /etc/nginx.bak/` |
| **Push** | SFTP upload `tmp/hardened_configs/{port}/` → `/etc/nginx/*` (reconstruct từ `.remote_base`) |
| **Note** | Không chạy `nginx -s reload` — nằm ngoài scope Executor |

`execute()` trả về:
```python
{ "status": "applied" | "failed", "error": str | None }
```

---

## Trạng Thái DB (SQLite — Bảng `Remediations`)

| Trạng thái | Điều kiện |
|---|---|
| `pending_approval` | Dry-Run xong, chờ Approve |
| `approved` | User nhấn Approve |
| `applied` | Executor push thành công |
| `failed` | SSH lỗi hoặc SFTP lỗi |

---

## File I/O Mapping

| Vai trò | Đường dẫn |
|---|---|
| **INPUT** | `tmp/contracts/scan_result/scan_result_{port}.json` |
| **INPUT** | `tmp/contracts/parsers_output/parser_output_{port}.json` |
| **WORK** | `tmp/hardened_configs/{port}/<relative_path>/` |
| **WORK** | `tmp/hardened_configs/{port}/.remote_base` |
| **AUDIT** | `tmp/contracts/mod_asts/mod_ast_{port}.json` |
| **LOG** | `logs/remedy_runs/remedy_{port}.log` |
| **OUTPUT** | `/etc/nginx/*` trên target server |
| **BACKUP** | `/etc/nginx.bak/*` trên target server |
