# Integration Test Document Outline

## 1. Purpose
- Describe the goal of the integration test suite: verify the full SecRemedy pipeline on multiple insecure Nginx configs, then confirm remediation improves compliance.
- State the two report sets used in this document:
  - `tmp/contracts/scan_report/scan_report_<port>.md` for the initial scan result.
  - `tmp/contracts/scan_again_report/scan_again_report_<port>.md` for the re-scan after remediation.
- Clarify that each test bundle contains one or more `nginx_raw_<port>` inputs under `tests/integration/*_uncomply/`.

## 2. Test Suite Overview
### 2.1 Bundles in `tests/integration/`
- `0_to_1_uncomply/`
  - `nginx_raw_2230/`
  - `nginx_raw_2240/`
  - `nginx_raw_2250/`
  - `nginx_raw_2260/`
  - `nginx_raw_2270/`
- `1_to_3_uncomply/`
  - `nginx_raw_2231/`
  - `nginx_raw_2234/`
  - `nginx_raw_2241/`
  - `nginx_raw_2244/`
  - `nginx_raw_2251/`
  - `nginx_raw_2254/`
  - `nginx_raw_2261/`
  - `nginx_raw_2264/`
  - `nginx_raw_2271/`
  - `nginx_raw_2274/`
- `3_to_4_uncomply/`
  - `nginx_raw_2232/`
  - `nginx_raw_2233/`
  - `nginx_raw_2235/`
  - `nginx_raw_2236/`
  - `nginx_raw_2242/`
  - `nginx_raw_2243/`
  - `nginx_raw_2245/`
  - `nginx_raw_2246/`
  - `nginx_raw_2252/`
  - `nginx_raw_2253/`
  - `nginx_raw_2255/`
  - `nginx_raw_2256/`
  - `nginx_raw_2262/`
  - `nginx_raw_2263/`
  - `nginx_raw_2265/`
  - `nginx_raw_2266/`
  - `nginx_raw_2272/`
  - `nginx_raw_2273/`
  - `nginx_raw_2275/`
  - `nginx_raw_2276/`
- `5_to_7_uncomply/`
  - `nginx_raw_2237/`
  - `nginx_raw_2238/`
  - `nginx_raw_2247/`
  - `nginx_raw_2248/`
  - `nginx_raw_2257/`
  - `nginx_raw_2258/`
  - `nginx_raw_2267/`
  - `nginx_raw_2268/`
  - `nginx_raw_2277/`
  - `nginx_raw_2278/`
- `10_to_12_uncomply/`
  - `nginx_raw_2239/`
  - `nginx_raw_2249/`
  - `nginx_raw_2259/`
  - `nginx_raw_2269/`
  - `nginx_raw_2279/`

### 2.2 Interpretation of bundle names
- Explain that `X_to_Y_uncomply` is the bundle naming convention for configs with multiple CIS violations.
- Mention that the smaller bundles are lighter insecure configs, while `10_to_12_uncomply` is the most severe set.
- Note that all bundles are processed by the same `run_tests.sh` pipeline.

## 3. How `run_tests.sh` Works
### 3.1 Preparation
- Remove and recreate `tmp/`.
- Copy every `nginx_raw_*` folder from each `*_uncomply/` directory into `tmp/`.
- Set `PYTHONPATH` to the project root.

### 3.2 Execution order
- Run parser before remediation:
  - `python -m core.scannerEng.parser --config tests/config_to_test/config_input_scanner_before_toFinal.json`
- Run scanner before remediation:
  - `python -m core.scannerEng.scanner --config tests/config_to_test/config_input_scanner_before_toFinal.json`
- Run remediation:
  - `python -m core.remedyEng.run_remedy --config tests/config_to_test/config_input_remedy_toFinal.json`
- Run scanner after remediation:
  - `python -m core.scannerEng.scanner --config tests/config_to_test/config_input_scanner_after_toFinal.json`

### 3.3 Outputs
- Before-scan reports are saved under `tmp/contracts/scan_report/`.
- After-remediation reports are saved under `tmp/contracts/scan_again_report/`.
- The document should explain that the before/after comparison is the main acceptance criterion.

## 4. Per-Bundle Results Summary
### 4.1 Bundle `0_to_1_uncomply`
- Ports: 2230, 2240, 2250, 2260, 2270.
- Common initial failures:
  - 2.4.2 in every port.
  - 5.3.2 in every port except where noted by the report.
- After remediation:
  - 5.3.2 is fixed.
  - 2.4.2 remains failing.

### 4.2 Bundle `1_to_3_uncomply`
- Ports: 2231, 2234, 2241, 2244, 2251, 2254, 2261, 2264, 2271, 2274.
- Common initial failures:
  - 2.4.2.
  - A mix of 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, and 5.3.2 depending on port.
- After remediation:
  - Most secondary violations are fixed.
  - 2.4.2 remains failing on all ports.

### 4.3 Bundle `3_to_4_uncomply`
- Ports: 2232, 2233, 2235, 2236, 2242, 2243, 2245, 2246, 2252, 2253, 2255, 2256, 2262, 2263, 2265, 2266, 2272, 2273, 2275, 2276.
- Common initial failures:
  - 2.4.2.
  - Additional failures often include 2.4.1, 2.5.1, 2.5.2, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2.
- After remediation:
  - Most bundle-specific issues are fixed.
  - 2.4.2 remains failing.
  - Some ports still keep 4.1.1 or 5.3.2 depending on their original combination.

### 4.4 Bundle `5_to_7_uncomply`
- Ports: 2237, 2238, 2247, 2248, 2257, 2258, 2267, 2268, 2277, 2278.
- Common initial failures:
  - 2.4.2.
  - A broader set of failures including 2.5.1, 2.5.2, 2.5.3, 2.5.4, 4.1.1, 5.3.1, 5.3.2.
- After remediation:
  - Most violations are corrected.
  - 2.4.2 remains failing.

### 4.5 Bundle `10_to_12_uncomply`
- Ports: 2239, 2249, 2259, 2269, 2279.
- Common initial failures:
  - 2.4.2.
  - 2.5.1, 2.5.2, 2.5.3, 2.5.4, 3.2, 3.4, 4.1.1, 5.3.1, 5.3.2.
- After remediation:
  - Most violations are fixed.
  - 2.4.2 remains failing.
  - In some ports, 5.3.2 also remains failing after remediation.

## 5. Per-Port Detail Section
- Add one subsection per port.
- Each port subsection should follow the same template:
  - Test bundle name.
  - Initial failed rules from `scan_report_<port>.md`.
  - Rules fixed after remediation from `scan_again_report_<port>.md`.
  - Rules still failing after remediation.
  - Before/after compliance score.
- Example template:
  - Port 2230
    - Before: 2.4.2, 5.3.2 failed.
    - After: 5.3.2 fixed; 2.4.2 still failing.
    - Score: 83% -> 92%.

### 5.1 Port group 2230-2239
- 2230
- 2231
- 2232
- 2233
- 2234
- 2235
- 2236
- 2237
- 2238
- 2239

### 5.2 Port group 2240-2249
- 2240
- 2241
- 2242
- 2243
- 2244
- 2245
- 2246
- 2247
- 2248
- 2249

### 5.3 Port group 2250-2259
- 2250
- 2251
- 2252
- 2253
- 2254
- 2255
- 2256
- 2257
- 2258
- 2259

### 5.4 Port group 2260-2269
- 2260
- 2261
- 2262
- 2263
- 2264
- 2265
- 2266
- 2267
- 2268
- 2269

### 5.5 Port group 2270-2279
- 2270
- 2271
- 2272
- 2273
- 2274
- 2275
- 2276
- 2277
- 2278
- 2279

## 6. Cross-Report Observations
- Rule 2.4.2 is the only rule that remains unfixed across all reports in the current dataset.
- The remediation engine consistently fixes most secondary violations such as 2.5.x, 3.2, 3.4, 4.1.1, 5.3.1, and 5.3.2.
- The before/after gap is strongest in the heavier bundles, where the compliance score rises substantially after remediation.
- The final report should note any ports that keep 5.3.2 or 4.1.1 after remediation.

## 7. Suggested Report Conclusion
- Summarize that the integration pipeline works end to end.
- State that remediation improves compliance in every tested bundle.
- Call out the persistent unresolved 2.4.2 issue as the main limitation.
- Recommend follow-up work on the remediation rule for 2.4.2 and a deeper investigation of the ports where 5.3.2 still fails after remediation.
