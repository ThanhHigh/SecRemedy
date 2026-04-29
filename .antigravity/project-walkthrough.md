# SecRemedy — Project Initialization Summary

## What is SecRemedy?

**SecRemedy** is an automated security assessment and remediation tool for **Nginx configurations** based on the **CIS Benchmark v3.0.0**. It:
1. **Fetches** Nginx configs from remote servers via SSH
2. **Parses** them into a JSON AST (using `crossplane`)
3. **Scans** the AST for CIS violations using detector plugins
4. **Remediates** violations with plugin-based AST mutations, with a dry-run diff preview before applying

---

## Project Structure

```
SecRemedy/
├── core/
│   ├── recom_registry.py          # Enum-based registry for all CIS rule metadata (O(1) lookup)
│   ├── scannerEng/                # Detection engine (READ-ONLY — do not modify)
│   │   ├── base_recom.py          # BaseRecom base class for all detectors
│   │   ├── fetcher.py             # SSH config downloader
│   │   ├── parser.py              # crossplane parser → JSON AST
│   │   ├── scanner.py             # Aggregates all detector results → scan_result.json
│   │   └── recommendations/       # One detector_NNN.py per CIS rule (12 rules)
│   └── remedyEng/                 # Remediation engine (primary working area)
│       ├── base_remedy.py         # BaseRemedy base class for all plugins
│       ├── ast_editor.py          # ASTEditor: add/replace/remove AST directives
│       ├── remediator.py          # RemediationManager: auto-discovers plugins
│       ├── run_remedy.py          # CLI entry + path normalization logic
│       ├── terminal_ui.py         # Interactive terminal UI for dry-run review
│       ├── diff_generator.py      # Unified diff generator
│       └── recommendations/       # One remediate_NNN.py per CIS rule (13 plugins)
├── contracts/                     # Data contracts: parser outputs + scan_result.json (READ-ONLY)
├── database/                      # SQLAlchemy ORM: Server, ScanResult, FailedRule, Remediation (READ-ONLY)
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── remedyEng/             # Unit tests for remedy plugins
│   │   │   ├── conftest.py        # Shared fixtures
│   │   │   ├── test_remediate_241.py
│   │   │   ├── test_remediate_242.py
│   │   │   ├── test_remediate_251.py
│   │   │   └── test_remediate_252.py  ← coverage gap here
│   │   └── scannerEng/
│   └── integration/
│       └── ...                    # Docker-based integration tests
├── docs/                          # CIS rule docs, impacts, rationales
└── .github/                       # Copilot brain (do not modify)
    ├── copilot-instructions.md    # Developer guidelines
    ├── agents/                    # Agent definitions (remedy-unit-test-generator)
    ├── skills/                    # Skill modules
    └── rules/restrict.md         # Hard boundaries: do not touch contracts/, scannerEng/, database/
```

---

## Implemented CIS Rules

| Rule ID | Detector | Remediation Plugin | Unit Test |
|---------|----------|--------------------|-----------|
| 2.4.1   | ✅ | ✅ | ✅ full |
| 2.4.2   | ✅ | ✅ | ✅ full |
| 2.5.1   | ✅ | ✅ | ✅ full |
| 2.5.2   | ✅ | ✅ | ⚠️ partial |
| 2.5.3   | ✅ | ✅ | ❌ missing |
| 2.5.4   | ✅ | ✅ | ❌ missing |
| 3.2     | ✅ | ✅ | ❌ missing |
| 3.4     | ✅ | ✅ | ❌ missing |
| 4.1.1   | ✅ | ✅ | ❌ missing |
| 5.1.1   | ✅ | ✅ | ❌ missing |
| 5.3.1   | ✅ | ✅ | ❌ missing |
| 5.3.2   | ✅ | ✅ | ❌ missing |
| —       | —  | ✅ `remediate_32.py` | — |

> **Gap**: Rules 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.1.1, 5.3.1, 5.3.2 have plugins but no unit tests yet.

---

## Key Architectural Patterns

### Data Flow
```
fetcher.py → nginx.conf (SSH)
    ↓
parser.py → contracts/parser_output_PORT.json  (crossplane JSON AST)
    ↓
scanner.py (detectors) → contracts/scan_result.json
    ↓
run_remedy.py (plugins + ASTEditor) → patched AST → unified diff → apply
```

### Plugin Contracts
- **Detector** (`BaseRecom`): implements `scan(parser_output)` → `List[Dict]` with violations
- **Remedy plugin** (`BaseRemedy`): implements `get_remedy()` → structured AST modifications
- **Auto-discovery**: both scanners and remedy plugins are auto-registered — no manual wiring needed

### Path Normalization (known gotcha)
- Paths between scan_result and AST may differ (relative vs absolute, `./` prefixes)
- Always use `_normalize_file_path()` helper from `run_remedy.py` when matching files

---

## Hard Boundaries (from `.github/rules/restrict.md`)

> ⛔ **Do not change or delete** files in `contracts/`, `core/scannerEng/`, or `database/`
> ⛔ **Do not read or use** `core/remedyEng/archive/`

---

## Available Agent

**`remedy-unit-test-generator`** — use this when creating or extending unit tests for remedy plugins in `core/remedyEng/recommendations/`. Trigger by asking to generate unit tests for a specific rule ID (e.g., `remediate_253.py`).

---

## Quick Commands

```bash
# Setup
python -m venv venv && source venv/bin/activate && pip install -r requirements.txt

# Start mock servers (Docker)
cd tests && docker-compose up -d
# Port 2221: violates rules 1–5 | Port 2222: violates rules 6–10

# Full pipeline (port 2221)
python core/scannerEng/fetcher.py -H localhost -P 2221 -u root -p root
python core/scannerEng/parser.py -P 2221
python -m core.scannerEng.scanner --ssh-port 2221
python core/remedyEng/run_remedy.py --input contracts/parser_output_2221.json --scan-result contracts/scan_result.json --dry-run

# Run unit tests
pytest tests/unit/
```
