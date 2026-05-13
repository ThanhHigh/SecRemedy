# SecRemedy Integration Test Report

## 1. Purpose

Integration test suite validates full SecRemedy pipeline: parse → scan → remediate → scan again. Two report sets track compliance:
- **Before**: `tmp/contracts/scan_report/scan_report_<port>.md` — initial CIS violations
- **After**: `tmp/contracts/scan_again_report/scan_again_report_<port>.md` — post-remediation re-scan

Test bundles under `tests/integration/*_uncomply/` contain nginx configs grouped by violation severity. Each `nginx_raw_<port>` folder = one test case.

---

## 2. Test Suite Overview

### 2.1 Bundle Inventory

| Bundle | Ports | Configs |
|--------|-------|---------|
| `0_to_1_uncomply/` | 2230, 2240, 2250, 2260, 2270 | 5 |
| `1_to_3_uncomply/` | 2231, 2234, 2241, 2244, 2251, 2254, 2261, 2264, 2271, 2274 | 10 |
| `3_to_4_uncomply/` | 2232, 2233, 2235, 2236, 2242, 2243, 2245, 2246, 2252, 2253, 2255, 2256, 2262, 2263, 2265, 2266, 2272, 2273, 2275, 2276 | 20 |
| `5_to_7_uncomply/` | 2237, 2238, 2247, 2248, 2257, 2258, 2267, 2268, 2277, 2278 | 10 |
| `10_to_12_uncomply/` | 2239, 2249, 2259, 2269, 2279 | 5 |
| **Total** | **50 ports** | **50 configs** |

### 2.2 Bundle Naming Convention

- **`X_to_Y_uncomply`**: Represents configs w/ CIS rule violations spanning rules X through Y
- Smaller bundles (0_to_1, 1_to_3) = lighter violation profiles
- Larger bundles (5_to_7, 10_to_12) = worst-case/stress-test scenarios
- All processed by same `run_tests.sh` pipeline for consistency

---

## 3. Integration Test Execution Flow

### 3.1 Test Preparation

```bash
# 1. Clean slate
rm -rf tmp/
mkdir -p tmp/

# 2. Seed test configs
find tests/integration -type d -name "*_to_*_uncomply" \
  -exec cp -r {}/. tmp/ \;

# 3. Export paths
export PYTHONPATH=$(pwd)
```

Result: `tmp/` contains all 50 `nginx_raw_<port>` folders flattened.

### 3.2 Execution Sequence

**Phase 1: Before Scan**
- Parser: `python -m core.scannerEng.parser --config tests/config_to_test/config_input_scanner_before_toFinal.json`
- Scanner: `python -m core.scannerEng.scanner --config tests/config_to_test/config_input_scanner_before_toFinal.json`
- Output: `tmp/contracts/scan_report/scan_report_<port>.md`

**Phase 2: Remediation**
- Remedy engine: `python -m core.remedyEng.run_remedy --config tests/config_to_test/config_input_remedy_toFinal.json`
- Modifies AST in-place using plugin-based fixes
- Outputs hardened configs to `tmp/remedies_output/`

**Phase 3: After Scan**
- Re-scan: `python -m core.scannerEng.scanner --config tests/config_to_test/config_input_scanner_after_toFinal.json`
- Output: `tmp/contracts/scan_again_report/scan_again_report_<port>.md`

### 3.3 Success Criterion

Remediation improves compliance on all test cases. Before/after diff shows rules fixed, rules persisting.

---

## 4. Per-Bundle Results

### 4.1 Bundle: `0_to_1_uncomply` — Minimal Violations

**Ports**: 2230, 2240, 2250, 2260, 2270 (5 configs)

| Port | Before Score | Failed Rules | After Score | Fixed | Unfixed | Status |
|------|--------------|--------------|-------------|-------|---------|--------|
| 2230 | 83% (10p, 2f) | 2.4.2, 5.3.2 | 92% (11p, 1f) | 5.3.2 | 2.4.2 | ✅ 50% fixed |
| 2240 | 83% (10p, 2f) | 2.4.2, 5.3.2 | 92% (11p, 1f) | 5.3.2 | 2.4.2 | ✅ 50% fixed |
| 2250 | 83% (10p, 2f) | 2.4.2, 5.3.2 | 92% (11p, 1f) | 5.3.2 | 2.4.2 | ✅ 50% fixed |
| 2260 | 75% (9p, 3f) | 2.4.2, 2.5.2, 5.3.2 | 92% (11p, 1f) | 2.5.2, 5.3.2 | 2.4.2 | ✅ 67% fixed |
| 2270 | 75% (9p, 3f) | 2.4.2, 2.5.2, 5.3.2 | 92% (11p, 1f) | 2.5.2, 5.3.2 | 2.4.2 | ✅ 67% fixed |

**Pattern**: All ports fix `5.3.2` (CSP header). All keep `2.4.2` (server_name deny) unfixed. Avg before score: 79.8%. Avg after score: 92.0%.

---

### 4.2 Bundle: `1_to_3_uncomply` — Moderate Violations

**Ports**: 2231, 2234, 2241, 2244, 2251, 2254, 2261, 2264, 2271, 2274 (10 configs)

| Port | Before Score | Failed Rules | After Score | Fixed | Unfixed | Status |
|------|--------------|--------------|-------------|-------|---------|--------|
| 2231 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2234 | 67% (8p, 4f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |
| 2241 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2244 | 67% (8p, 4f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |
| 2251 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2254 | 67% (8p, 4f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |
| 2261 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2264 | 58% (7p, 5f) | 2.4.2, 2.5.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2271 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2274 | 58% (7p, 5f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |

**Pattern**: Strong remediation across logging (3.2, 3.4) and header directives (2.5.x). 2.4.2 persists. Avg before score: 60.7%. Avg after score: 92.0%.

---

### 4.3 Bundle: `3_to_4_uncomply` — Heavy Violations

**Ports**: 2232, 2233, 2235, 2236, 2242, 2243, 2245, 2246, 2252, 2253, 2255, 2256, 2262, 2263, 2265, 2266, 2272, 2273, 2275, 2276 (20 configs)

| Port | Before Score | Failed Rules | After Score | Fixed | Unfixed | Status |
|------|--------------|--------------|-------------|-------|---------|--------|
| 2232 | 50% (6p, 6f) | 2.4.1, 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 83% (10p, 2f) | 2.4.1, 2.5.2, 3.2, 3.4 | 2.4.2, 4.1.1 | ⚠️ 67% fixed |
| 2233 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2235 | 50% (6p, 6f) | 2.4.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 83% fixed |
| 2236 | 67% (8p, 4f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |
| 2242 | 42% (5p, 7f) | 2.4.1, 2.4.2, 2.5.1, 2.5.2, 3.2, 3.4, 5.3.2 | 83% (10p, 2f) | 2.4.1, 2.5.1, 2.5.2, 3.2, 3.4 | 2.4.2, 4.1.1 | ⚠️ 71% fixed |
| 2243 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2245 | 50% (6p, 6f) | 2.4.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 83% fixed |
| 2246 | 67% (8p, 4f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |
| 2252 | 50% (6p, 6f) | 2.4.1, 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 83% (10p, 2f) | 2.4.1, 2.5.2, 3.2, 3.4 | 2.4.2, 4.1.1 | ⚠️ 67% fixed |
| 2253 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2255 | 50% (6p, 6f) | 2.4.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 83% fixed |
| 2256 | 67% (8p, 4f) | 2.4.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 75% fixed |
| 2262 | 42% (5p, 7f) | 2.4.1, 2.4.2, 2.5.1, 2.5.2, 3.2, 3.4, 5.3.2 | 83% (10p, 2f) | 2.4.1, 2.5.1, 2.5.2, 3.2, 3.4 | 2.4.2, 4.1.1 | ⚠️ 71% fixed |
| 2263 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2265 | 42% (5p, 7f) | 2.4.2, 2.5.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2266 | 58% (7p, 5f) | 2.4.2, 2.5.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2272 | 42% (5p, 7f) | 2.4.1, 2.4.2, 2.5.1, 2.5.2, 3.2, 3.4, 5.3.2 | 83% (10p, 2f) | 2.4.1, 2.5.1, 2.5.2, 3.2, 3.4 | 2.4.2, 4.1.1 | ⚠️ 71% fixed |
| 2273 | 58% (7p, 5f) | 2.4.2, 2.5.2, 3.2, 3.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2275 | 42% (5p, 7f) | 2.4.2, 2.5.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2276 | 58% (7p, 5f) | 2.4.2, 2.5.2, 2.5.3, 2.5.4, 5.3.2 | 92% (11p, 1f) | 2.5.2, 2.5.3, 2.5.4, 5.3.2 | 2.4.2 | ✅ 80% fixed |

**Pattern**: Heavy bundle. Most configs fix 67-86% violations. Ports with 2.4.1 before remediation end at 4.1.1 after remediation on the 2232/2242/2252/2262/2272 path. Avg before score: 53.4%. Avg after score: 89.8%.

---

### 4.4 Bundle: `5_to_7_uncomply` — Severe Violations

**Ports**: 2237, 2238, 2247, 2248, 2257, 2258, 2267, 2268, 2277, 2278 (10 configs)

| Port | Before Score | Failed Rules | After Score | Fixed | Unfixed | Status |
|------|--------------|--------------|-------------|-------|---------|--------|
| 2237 | 42% (5p, 7f) | 2.4.2, 2.5.2, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2238 | 42% (5p, 7f) | 2.4.2, 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2247 | 42% (5p, 7f) | 2.4.2, 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2248 | 42% (5p, 7f) | 2.4.2, 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2257 | 42% (5p, 7f) | 2.4.2, 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2258 | 42% (5p, 7f) | 2.4.2, 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2267 | 42% (5p, 7f) | 2.4.2, 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2268 | 42% (5p, 7f) | 2.4.2, 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |
| 2277 | 42% (5p, 7f) | 2.4.2, 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.2, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 80% fixed |
| 2278 | 42% (5p, 7f) | 2.4.2, 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 92% (11p, 1f) | 2.5.1, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2 | 2.4.2 | ✅ 86% fixed |

**Pattern**: Severe bundle. Every port improves to 92%. Avg before score: 40.2%. Avg after score: 92.0%.

---

### 4.5 Bundle: `10_to_12_uncomply` — Worst-Case Violations

**Ports**: 2239, 2249, 2259, 2269, 2279 (5 configs)

| Port | Before Score | Failed Rules | After Score | Fixed | Unfixed | Status |
|------|--------------|--------------|-------------|-------|---------|--------|
| 2239 | 17% (2p, 10f) | 2.4.2, 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 83% (10p, 2f) | 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1 | 2.4.2, 5.3.2 | ⚠️ 80% fixed |
| 2249 | 17% (2p, 10f) | 2.4.2, 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 83% (10p, 2f) | 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1 | 2.4.2, 5.3.2 | ⚠️ 80% fixed |
| 2259 | 17% (2p, 10f) | 2.4.2, 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 83% (10p, 2f) | 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1 | 2.4.2, 5.3.2 | ⚠️ 80% fixed |
| 2269 | 25% (3p, 9f) | 2.4.2, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 83% (10p, 2f) | 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1 | 2.4.2, 5.3.2 | ⚠️ 78% fixed |
| 2279 | 17% (2p, 10f) | 2.4.2, 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2 | 83% (10p, 2f) | 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1 | 2.4.2, 5.3.2 | ⚠️ 80% fixed |

**Pattern**: Stress-test bundle. All start 17-25% (9-10 violations). Fix 78-80% → 83% final score. Two rules persist: **2.4.2 (all)** and **5.3.2 (all)**. Avg before score: 18.6%. Avg after score: 83.0%.

---

## 5. Cross-Report Analysis

### 5.1 Remediation Success Rate

| Metric | Result |
|--------|--------|
| Total configs scanned | 50 |
| Reports generated | 50 before + 50 after |
| Complete reports | 50 pairs |
| Missing reports | 0 |
| Avg improvement | +38.8% → 90.2% |
| Min improvement | +9% (port 2230) |
| Max improvement | +66% (port 2239) |
| Avg failed rules before | 4.8 |
| Avg failed rules after | 1.2 |

### 5.2 Rule-Level Remediation Stats

| Rule | Fixed? | Frequency | Notes |
|------|--------|-----------|-------|
| 2.4.1 | ✅ | 5 before / 0 after | Recovered on all 5 ports |
| 2.4.2 | ❌ | 50 before / 50 after | Never fixed across tests |
| 2.5.1 | ✅ | 12 before / 0 after | Recovered on all 12 ports |
| 2.5.2 | ✅ | 35 before / 0 after | Recovered on all 35 ports |
| 2.5.3 | ✅ | 25 before / 0 after | Recovered on all 25 ports |
| 2.5.4 | ✅ | 25 before / 0 after | Recovered on all 25 ports |
| 3.2 | ✅ | 20 before / 0 after | Recovered on all 20 ports |
| 3.4 | ✅ | 20 before / 0 after | Recovered on all 20 ports |
| 4.1.1 | ⚠️ | 20 before / 5 after | Fixed on 20 original failures; appears on 5 ports after remediation: 2232, 2242, 2252, 2262, 2272 |
| 5.3.1 | ✅ | 20 before / 0 after | Recovered on all 20 ports |
| 5.3.2 | ⚠️ | 50 before / 5 after | Recovered on 45 ports; remains on 2239, 2249, 2259, 2269, 2279 |

### 5.3 Persistent Failures

**Rule 2.4.2** (deny undefined server_name):
- Unfixed on **all 50 ports** before and after remediation
- Still the main unresolved gap in this test set
- Root cause likely in remediation logic or a structural nginx constraint

**Rule 5.3.2** (CSP header):
- Unfixed on **5 worst-case ports**: 2239, 2249, 2259, 2269, 2279
- All in 10_to_12_uncomply bundle
- Suggests complex interaction w/ severity level or missing CSP policy template

**Rule 4.1.1** (HTTP→HTTPS redirect):
- Removed from its original 20 failures, but reappears after remediation on **5 ports**: 2232, 2242, 2252, 2262, 2272
- All 5 are in `3_to_4_uncomply`
- This is a remediation regression, not just partial coverage

---

## 6. Test Execution Summary

### 6.1 Bundle Performance

| Bundle | Ports | Score Before | Score After | Improvement | Fix Rate |
|--------|-------|--------------|-------------|-------------|----------|
| `0_to_1_uncomply/` | 5 | 79.8% | 92.0% | +12.2% | 1.4 rules fixed/port |
| `1_to_3_uncomply/` | 10 | 60.7% | 92.0% | +31.3% | 2.7 rules fixed/port |
| `3_to_4_uncomply/` | 20 | 53.4% | 89.8% | +36.4% | 3.6 rules fixed/port |
| `5_to_7_uncomply/` | 10 | 40.2% | 92.0% | +51.8% | 5.2 rules fixed/port |
| `10_to_12_uncomply/` | 5 | 18.6% | 83.0% | +64.4% | 5.8 rules fixed/port |

### 6.2 Coverage Notes

- All 50 `scan_report` files exist.
- All 50 `scan_again_report` files exist.
- No coverage gaps in current report set.
- Remaining discussion is about remediation quality, not report availability.

---

## 7. Key Findings

### 7.1 Strengths

✅ **End-to-end pipeline works**: Parser → Scanner → Remediate → Re-scan completes on all configs

✅ **High remediation rate**: most violations removed; bundle averages improve by 12.2% to 64.4%

✅ **Consistent improvements**: Every scanned port shows compliance gain (min +9%, max +66%)

✅ **Rule-specific success**: 2.5.x, 3.2, 3.4, and 5.3.1 fully recovered when present

✅ **Stress testing**: Heavy violation bundle (10_to_12) still climbs from 18.6% to 83.0%

### 7.2 Limitations

❌ **Rule 2.4.2 never fixed**: Persistent across all 50 ports. Blocks near-perfect compliance

❌ **Partial failures / regressions**: 5.3.2 remains on 5 ports; 4.1.1 reappears on 5 ports after remediation

❌ **Incomplete remediate coverage**: CSP header (5.3.2) and server_name deny (2.4.2) still need work; 4.1.1 needs regression handling

### 7.3 Recommendations

1. **Investigate 2.4.2 remediation**: 
   - Check if `remediate_242.py` exists and is auto-discovered
   - Verify remediation logic for `server_name` directive
   - Consider if manual nginx.conf structure blocks automatic injection

2. **Fix 5.3.2 on 10_to_12 bundle**:
   - Audit CSP plugin behavior under heavy violation load
   - Check for edge-case rule interactions
   - Test w/ explicit CSP policy template

3. **Audit 4.1.1 regression**:
   - Verify HTTP→HTTPS redirect plugin does not introduce new failures
   - Add conflict-detection logic for the 5 regressions in `3_to_4_uncomply`

4. **Use current coverage as baseline**:
   - Keep `run_tests.sh` as regression baseline
   - Track before/after changes on all 50 configs

5. **Add unit tests**:
   - Build isolated tests for 2.4.2, 5.3.2, 4.1.1 remediation plugins
   - Mock AST to avoid end-to-end pipeline dependency

---

## 8. Conclusion

SecRemedy integration test suite validates full remediation pipeline on 50 configs spanning 5 severity tiers. Results show:

- **Pipeline health**: ✅ Works end-to-end
- **Remediation effectiveness**: ✅ bundle averages improve by 12.2% to 64.4%
- **Compliance gain**: ✅ Avg +38.8% improvement across all 50 configs
- **Known gaps**: ⚠️ Rule 2.4.2 unfixed; 5.3.2 remains on 5 ports; 4.1.1 introduced on 5 ports after remediation

Further work on rule 2.4.2 remediation will push results toward near-total compliance. 4.1.1 regression must be handled before calling remediation stable.

