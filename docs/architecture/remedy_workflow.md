# RemedyEng Data Flow: Parser Output → Scan Result → Final AST

## High Level: Three Inputs, One Output

```
[Parser Output JSON]       [Scan Result JSON]
  (Crossplane AST)          (CIS violations)
         │                         │
         └────────┬────────────────┘
                  ▼
           [Remediator]
                  │
         ┌────────┼────────────┬─────────┐
         ▼        ▼            ▼         ▼
    Remediate241 Remediate251 ... RemediateN
         │        │            │         │
         └────────┼────────────┼─────────┘
                  ▼
         [Patch Aggregator]
                  │
         ┌────────┼────────────┐
         ▼        ▼            ▼
      File1    File2  ...   FileN
      Patches  Patches      Patches
         │        │            │
         └────────┼────────────┘
                  ▼
         [Apply Patches]
         (Reverse path order)
                  │
                  ▼
         [Modified AST]
                  │
                  ▼
         [Export Manager]
                  │
                  ▼
        [nginx.conf Files]
```

---

## Input 1: Parser Output (Baseline AST)

**Location**: `contracts/parser_output_*.json`

**Format**:
```json
{
  "config": [
    {
      "file": "/etc/nginx/nginx.conf",
      "parsed": [
        {
          "directive": "events",
          "block": [
            {"directive": "worker_connections", "args": ["1024"]}
          ]
        },
        {
          "directive": "http",
          "block": [
            {
              "directive": "server",
              "block": [
                {"directive": "listen", "args": ["80"]},
                {"directive": "server_tokens", "args": ["on"]}
              ]
            }
          ]
        }
      ]
    }
  ],
  "status": "ok"
}
```

**Key**: Full nginx config structure. Every file → `parsed` array = directive nodes + blocks.

---

## Input 2: Scan Result (Violations)

**Location**: `contracts/scan_result.json`

**Format**:
```json
{
  "recommendations": [
    {
      "file": "/etc/nginx/nginx.conf",
      "id": "CIS_2_4_1",
      "violations": [
        {
          "context": ["config", 0, "parsed", 2, "block", 0, "block", 1],
          "action": "replace",
          "directive": "server_tokens",
          "args": ["off"]
        }
      ]
    }
  ]
}
```

**Key**: Path + action + values for each violation. Context = full route from JSON root.

---

## Stage 1: Remediator Split (Per Rule)

**Process**:
1. For each `Remediate_*` plugin class (241, 251, etc.):
   - Create instance
   - Call `read_child_scan_result(scan_result)`
     → Extract violations matching rule ID
     → Populate: `remedy.child_scan_result = {file: [violations]}`
   - Call `read_child_ast_config(parser_output)`
     → Extract AST for those files only
     → Populate: `remedy.child_ast_config = {file: {parsed: [...]}}`

**Result**: Each remedy knows ONLY its violations + relevant AST.

Example (Remediate251):
```
Input scan_result.json (10 recommendations, mixed IDs)
    ▼
read_child_scan_result()  
    ▼
Filter: only CIS_2_5_1 violations
    ▼
remediate251.child_scan_result = {
  "/etc/nginx/nginx.conf": [
    {context: [...], action: "add", directive: "ssl_certificate", ...},
    {context: [...], action: "add", directive: "ssl_key", ...}
  ]
}
    ▼
read_child_ast_config()
    ▼
Extract parsed for /etc/nginx/nginx.conf
    ▼
remediate251.child_ast_config = {
  "/etc/nginx/nginx.conf": {
    parsed: [full AST for that file]
  }
}
```

---

## Stage 2: Per-Remedy Patch Generation

**Method**: `remedy.collect_patches()`

**Process**:
1. For each violation in `child_scan_result`:
   - Extract context path: `["config", 0, "parsed", 5, "block", 2]`
   - Convert to **relative** path (from parsed):
     - Find "parsed" index in context
     - Take everything after it: `[5, "block", 2]`
     - This = exact_path (how to navigate AST)
   - Build patch dict:
     ```json
     {
       "action": "replace",
       "exact_path": [5, "block", 2],
       "directive": "server_tokens",
       "args": ["off"]
     }
     ```

2. Return: `{file: [patch1, patch2, ...]}`

**Output** (per remedy):
```json
{
  "/etc/nginx/nginx.conf": [
    {"action": "delete", "exact_path": [1, "block", 0, "block", 3]},
    {"action": "add", "exact_path": [1, "block", 0, "block"], "args": ["off"]}
  ]
}
```

---

## Stage 3: Aggregate Patches (Across All Rules)

**Process**:
1. Remediator collects patches from all remedies
2. Merge by file:
   ```
   File: /etc/nginx/nginx.conf
     ├─ Patches from Remediate241
     ├─ Patches from Remediate251
     ├─ Patches from Remediate241
     └─ Patches from RemediateN
   
   File: /etc/nginx/conf.d/default.conf
     ├─ Patches from Remediate241
     └─ Patches from Remediate251
   ```

3. Store: `Remediator.aggregated_patches = {file: [all_patches_for_file]}`

**Result**: All fixes from all rules grouped by file, ready to apply.

---

## Stage 4: Apply Patches (Core Fix Logic)

**Process** (per file):

1. **Get baseline**: Extract `parser_output["config"][N]["parsed"]` for target file
2. **Deep copy**: `parsed_copy = deepcopy(baseline_parsed)`
3. **Sort patches**: Reverse order by `exact_path` (deletes first, highest indices first)
   - Why? Delete at index 3 before index 1 (avoid index shift)
4. **Apply each patch**:
   - `ASTEditor.delete(parsed_copy, exact_path)` → Remove node
   - `ASTEditor.replace(parsed_copy, exact_path, args)` → Modify args
   - `ASTEditor.add(parsed_copy, parent_path, directive, args)` → Insert node
5. **Store result**: `modified_ast[file]["parsed"] = parsed_copy`

**Before**:
```json
{
  "file": "/etc/nginx/nginx.conf",
  "parsed": [
    {"directive": "http", "block": [
      {"directive": "server", "block": [
        {"directive": "listen", "args": ["80"]},
        {"directive": "server_tokens", "args": ["on"]},
        {"directive": "ssl_certificate", "args": []}
      ]}
    ]}
  ]
}
```

**After patches applied**:
```json
{
  "file": "/etc/nginx/nginx.conf",
  "parsed": [
    {"directive": "http", "block": [
      {"directive": "server", "block": [
        {"directive": "listen", "args": ["443"]},
        {"directive": "server_tokens", "args": ["off"]},
        {"directive": "ssl_certificate", "args": ["/path/cert"]}
      ]}
    ]}
  ]
}
```

---

## Stage 5: Merge All Modified ASTs

**Process**:
1. For each file in `aggregated_patches`:
   - Apply ALL its patches (from all rules) → modified_ast[file]

2. For files NOT in `aggregated_patches`:
   - Keep baseline (no changes)

**Result**: `modified_ast` = complete AST with ALL rule fixes applied.

**Example**:
```
Input: parser_output (5 files)
       aggregated_patches (3 files have fixes)

Output: modified_ast
  ├─ file1 (modified) — all patches applied
  ├─ file2 (modified) — all patches applied
  ├─ file3 (modified) — all patches applied
  ├─ file4 (unchanged) — baseline copy
  └─ file5 (unchanged) — baseline copy
```

---

## Stage 6: Validate & Export

**Validation**:
- AST structure integrity check
- Directive match validation
- Syntax test: `nginx -t`

**Export**:
1. For each file in modified_ast:
   - Render AST → nginx.conf text: `ASTEditor.ast_to_config_text(parsed)`
   - Write to output dir: `remediated_output_*/etc/nginx/...`
   - Preserve directory structure
2. Create tarball: `remediated_output_*.tar.gz`

**Output files**:
```
remediated_output_2221/
  ├─ etc/nginx/nginx.conf (modified)
  ├─ etc/nginx/conf.d/default.conf (modified)
  ├─ etc/nginx/conf.d/other.conf (unchanged)
  └─ ...

remediated_output_2221.tar.gz (all files packaged)
```

---

## How Each Remediate Contributes: Flow Summary

```
Remediate241 (Rule 2.4.1 - Listen Port)
  ├─ read_child_scan_result()      ← Extract: violations for CIS_2_4_1
  ├─ read_child_ast_config()       ← Extract: AST for affected files
  ├─ collect_patches()             ← Generate: delete/replace listen directives
  └─ Output patches                ← [{file: "/...", patches: [delete 8080]}]

Remediate251 (Rule 2.5.1 - Server Tokens)
  ├─ read_child_scan_result()      ← Extract: violations for CIS_2_5_1
  ├─ read_child_ast_config()       ← Extract: AST for affected files
  ├─ collect_patches()             ← Generate: replace server_tokens on → off
  └─ Output patches                ← [{file: "/...", patches: [replace on → off]}]

...similar for all other rules...

Aggregator merges ALL patches by file:
  {
    "/etc/nginx/nginx.conf": [
      {from Remediate241: delete listen 8080},
      {from Remediate251: replace server_tokens on → off},
      {from RemediateXYZ: add ssl_certificate ...},
      ...all rules combined...
    ]
  }

Apply patches (ONCE per file):
  parsed_copy = deepcopy(baseline)
  for patch in sorted_patches (reverse order):
    apply_patch(parsed_copy, patch)
  modified_ast[file] = parsed_copy

Export:
  final_nginx_conf = render(modified_ast[file])
  write(output_dir/file, final_nginx_conf)
```

---

## Key Guarantees

| Guarantee | How |
|-----------|-----|
| All patches applied | Aggregator collects from all rules, applies all patches per file |
| Correct order | Patches sorted in reverse (deletes before adds, high indices first) |
| No index corruption | Deep copy baseline, reverse-sort prevents shift issues |
| No file loss | Baseline files without violations copied unchanged |
| Syntax valid | `nginx -t` validates after all modifications |
| User review | Diff shown before export (dry-run or interactive mode) |

---

## Entry Point: run_remedy.py

```bash
python core/remedyEng/run_remedy.py \
  --input contracts/parser_output_2221.json \
  --scan-result contracts/scan_result.json \
  --dry-run

# Remediator flow:
#   1. Load inputs (Stage 1)
#   2. Split per remedy (Stage 2)
#   3. Generate patches (Stage 3)
#   4. Aggregate (Stage 4)
#   5. Apply to AST (Stage 5)
#   6. Export (Stage 6)
#   7. Show diff (dry-run) / Apply (interactive)
```
