# Luồng Dữ Liệu Tổng Quan — SecRemedy

## Tầng 1: Frontend — Streamlit UI

| Bước | UI Component | Hành động |
|---|---|---|
| 1 | Server Form | Nhận SSH creds (ip, port, user, pass) per server |
| 2 | Scanner Param Input | User điền `authorized_ports`, `authorized_ips`, `strict_private`, `scan_server` → ghi `before_remediation.json` |
| 3 | Pre-check UI | Hiển thị kết quả `nginx -t` (OK / FAIL + stderr) |
| 4 | Scan Results UI | Đọc `scan_result_<port>.json` → hiển thị vi phạm CIS + điểm |
| 5 | Remediation Param Input | Thu params user cho các rule cần input → ghi remediation config JSON |
| 6 | Dry-Run UI | Đọc `diff_<port>.json` → hiển thị Unified Diff |
| 7 | Approve Button | User chốt → Engine chạy Execute |
| 8 | Execute Status UI | Hiển thị kết quả push config (Success / Error) |

**Nguyên tắc:** Streamlit ↔ Engine giao tiếp hoàn toàn qua JSON file — không gọi nhau trực tiếp.

---

## Tầng 2: Core Engines

### Scanner Engine

```
SSH Fetcher
  └─ Kéo /etc/nginx/* về local (/tmp/)
       └─ Crossplane Parser
            └─ Text → AST JSON (<port>_ast.json)
                 └─ CIS Rules Evaluator
                      └─ Duyệt AST qua BaseRule
                           └─ Ghi scan_result_<port>.json + SQLite
```

### Remediation Engine

```
scan_result_<port>.json
  └─ Scan Result Reader
       └─ AST Locator (exact_path → node ref)
            └─ AST Injector (add / replace / delete)
                 └─ Crossplane Builder
                      └─ tmp/hardened_configs/<port>_hardened.conf
                           └─ Diff Generator (difflib)
                                └─ diff_<port>.json → Dry-Run UI
```

### Safe Pipeline (chỉ chạy sau Approve)

```
SSH Backup
  └─ cp -R /etc/nginx/ /etc/nginx.bak/ trên server
       └─ Executor (SFTP)
            └─ Push hardened config → /etc/nginx/* trên server
```

---

## Tầng 3: File I/O — "Hợp Đồng" JSON

| File | Vai trò |
|---|---|
| `tests/configs/before_remediation.json` | Input chính cho Scanner Engine — `servers[]` array gồm SSH creds + paths + scan params |
| `tmp/contracts/parsers_output/<port>_ast.json` | AST parse output (Parser → Locator) |
| `tmp/contracts/scan_result/<port>_scan_result.json` | Kết quả scan CIS (Scanner → Remediation Engine + UI) |
| `tmp/hardened_configs/<port>_hardened.conf` | Config đã hardened (Builder → Diff Generator) |
| `diff_<port>.json` | Unified Diff (Remediation Engine → Dry-Run UI) |

---

## Tầng 4: Infrastructure

### Pre-check Gate

`nginx -t` chạy trước scan:
- **FAIL** → báo lỗi stderr lên UI, dừng toàn bộ luồng
- **OK** → tiếp tục Scanner Engine

### SQLite Database

| Bảng | Mục đích |
|---|---|
| `Servers` | Thông tin target server |
| `ScanResults` | Kết quả quét CIS |
| `Remediations` | Trạng thái: `pending` / `approved` / `applied` / `failed` |

---

## Sơ đồ Tổng Quan

```
[ USER ]
    │ SSH creds + scan params
    ▼
[ Streamlit — Server Form ]
    │ ghi before_remediation.json
    ▼
[ Pre-check: nginx -t ]
    │ FAIL → dừng     OK → tiếp
    ▼
[ Scanner Engine ]
    │ SSH Fetch → Parse → Rules Eval → ghi scan_result.json
    ▼
[ Streamlit — Scan Results UI ]
    │ đọc scan_result.json → hiển thị vi phạm
    ▼
[ Remediation Engine — Dry-Run ]
    │ AST Locate → Inject → Build → Diff → ghi diff.json
    ▼
[ Streamlit — Dry-Run UI ]
    │ đọc diff.json → hiển thị Unified Diff
    ▼
[ APPROVE GATE — User nhấn Approve ]
    │
    ├──[ SSH Backup: cp -R /etc/nginx/ ]
    │
    └──[ Executor: SFTP push hardened config ]
              │
              ▼
    [ TARGET SERVER — /etc/nginx/* hardened ]
              │
              ▼
    [ SQLite: Servers | ScanResults | Remediations ]
```
