# Scan Report Mismatch

- Compare: `tmp/contracts/scan_report` vs `tmp/contracts/scan_report_after`
- Missing in `scan_report_after`: `scan_report_2267.md`, `scan_report_2268.md`, `scan_report_2269.md`, `scan_report_2270.md`, `scan_report_2271.md`, `scan_report_2272.md`
- Extra in `scan_report_after`: none
- Common files `scan_report_2220.md` to `scan_report_2266.md`: all content differs
- Pattern: before set shows failing compliance; after set shows passing compliance
- Main gap after re-scan: tail reports 2267–2272 not regenerated in after folder