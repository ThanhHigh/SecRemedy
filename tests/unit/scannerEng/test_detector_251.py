"""
Unit tests cho Detector251 — CIS Benchmark 2.5.1
"Đảm bảo chỉ thị server_tokens được cấu hình là `off`"
"""

import pytest
from core.scannerEng.recommendations.detector_251 import Detector251


@pytest.fixture
def detector():
    """Trả về một instance Detector251 mới cho mỗi test."""
    return Detector251()


def _directive(name: str, args: list, block: list = None) -> dict:
    """Hàm hỗ trợ: tạo một dictionary directive tối thiểu của crossplane."""
    d = {"directive": name, "args": args}
    if block is not None:
        d["block"] = block
    return d


def _make_parser_output(parsed_directives: list, filepath: str = "/etc/nginx/nginx.conf") -> dict:
    """Hàm hỗ trợ: bọc các directive trong một cấu trúc parser_output tối thiểu của crossplane."""
    return {
        "config": [
            {
                "file": filepath,
                "parsed": parsed_directives,
            }
        ]
    }


# ──────────────────────────────────────────────────────────────────────────────
# Phần 1 — Kiểm tra tính đúng đắn của Metadata (3 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestMetadata:
    def test_id(self, detector):
        assert detector.id == "2.5.1"

    def test_title_contains_server_tokens(self, detector):
        assert "server_tokens" in detector.title.lower()

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate(): các trường hợp tuân thủ (phải trả về None) (4 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive):
        return detector.evaluate(directive, self.FILEPATH, [], self.EXACT_PATH)

    def test_explicit_server_tokens_off(self, detector):
        """Cấu hình server_tokens off; (hợp lệ)"""
        assert self._eval(detector, _directive(
            "server_tokens", ["off"])) is None

    def test_http_block_with_server_tokens(self, detector):
        """Khối http có chứa server_tokens (bỏ qua thêm mới để tránh trùng lặp)"""
        http_block = _directive("http", [], [
            _directive("server_tokens", ["on"])
        ])
        assert self._eval(detector, http_block) is None

    def test_non_target_directive_server_name(self, detector):
        """Bỏ qua chỉ thị không liên quan"""
        assert self._eval(detector, _directive(
            "server_name", ["example.com"])) is None

    def test_non_target_directive_listen(self, detector):
        """Bỏ qua chỉ thị không liên quan"""
        assert self._eval(detector, _directive("listen", ["80"])) is None


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): các trường hợp không tuân thủ (8 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0]

    def _eval(self, detector, directive):
        return detector.evaluate(directive, self.FILEPATH, [], self.EXACT_PATH)

    # --- Trường hợp cấu hình sai rõ ràng ---

    def test_server_tokens_on(self, detector):
        result = self._eval(detector, _directive("server_tokens", ["on"]))
        assert result is not None
        assert result["file"] == self.FILEPATH
        assert len(result["remediations"]) == 1
        rem = result["remediations"][0]
        assert rem["action"] == "replace"
        assert rem["directive"] == "server_tokens"
        assert rem["args"] == ["off"]
        assert rem["context"] == self.EXACT_PATH

    def test_server_tokens_build(self, detector):
        result = self._eval(detector, _directive("server_tokens", ["build"]))
        assert result is not None
        rem = result["remediations"][0]
        assert rem["action"] == "replace"
        assert rem["args"] == ["off"]

    def test_server_tokens_empty_string(self, detector):
        result = self._eval(detector, _directive("server_tokens", [""]))
        assert result is not None

    # --- Trường hợp thiếu cấu hình ---

    def test_http_block_missing_server_tokens(self, detector):
        http_block = _directive("http", [], [
            _directive("server", [], [])
        ])
        result = self._eval(detector, http_block)
        assert result is not None

    # --- Kiểm tra cấu trúc dữ liệu phản hồi đối với hành động Replace ---

    def test_replace_action_metadata(self, detector):
        result = self._eval(detector, _directive("server_tokens", ["on"]))
        assert result["file"] == self.FILEPATH
        remediation = result["remediations"][0]
        assert remediation["context"] == self.EXACT_PATH

    def test_replace_action_content(self, detector):
        result = self._eval(detector, _directive("server_tokens", ["build"]))
        remediation = result["remediations"][0]
        assert remediation["action"] == "replace"
        assert remediation["directive"] == "server_tokens"
        assert remediation["args"] == ["off"]

    # --- Kiểm tra cấu trúc dữ liệu phản hồi đối với hành động Add ---

    def test_add_action_metadata(self, detector):
        http_block = _directive("http", [], [])
        result = self._eval(detector, http_block)
        assert result["file"] == self.FILEPATH
        remediation = result["remediations"][0]
        assert remediation["context"] == self.EXACT_PATH + ["block"]

    def test_add_action_content(self, detector):
        http_block = _directive("http", [], [])
        result = self._eval(detector, http_block)
        remediation = result["remediations"][0]
        assert remediation["action"] == "add"
        assert remediation["directive"] == "server_tokens"
        assert remediation["args"] == ["off"]


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): Toàn bộ đường ống (10 test cases)
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    # --- Cấu hình an toàn ---

    def test_safe_http_block_with_off(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [
                _directive("server_tokens", ["off"])
            ])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_empty_config(self, detector):
        findings = detector.scan({"config": []})
        assert findings == []

    def test_other_contexts_no_violation(self, detector):
        parser_output = _make_parser_output([
            _directive("events", [], [
                _directive("worker_connections", ["1024"])
            ])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    # --- Xử lý vi phạm thay thế (Replace) ---

    def test_replace_detects_on(self, detector):
        parser_output = _make_parser_output([
            _directive("server_tokens", ["on"])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_replace_action_is_correct(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [
                _directive("server_tokens", ["build"])
            ])
        ])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["action"] == "replace"
        assert findings[0]["remediations"][0]["args"] == ["off"]

    # --- Xử lý vi phạm thêm mới (Add) ---

    def test_add_detects_missing_in_http(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_add_action_is_correct(self, detector):
        parser_output = _make_parser_output([
            _directive("http", [], [])
        ])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["action"] == "add"
        assert findings[0]["remediations"][0]["args"] == ["off"]

    # --- Gom nhóm lỗi (Grouping) ---

    def test_multiple_violations_same_file_grouped(self, detector):
        parser_output = _make_parser_output([
            # Thiếu server_tokens -> sinh hành động Add
            _directive("http", [], []),
            _directive("server", [], [
                # Cấu hình sai -> sinh hành động Replace
                _directive("server_tokens", ["on"])
            ])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    # --- Nhiều file cấu hình ---

    def test_scan_multiple_files_both_invalid(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx.conf",
                    # Thiếu server_tokens
                    "parsed": [_directive("http", [], [])]
                },
                {
                    "file": "/etc/nginx/conf.d/app.conf",
                    # Giá trị sai
                    "parsed": [_directive("server_tokens", ["on"])]
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2

    def test_scan_multiple_files_one_valid_one_invalid(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx.conf",
                    # Hợp lệ
                    "parsed": [_directive("http", [], [_directive("server_tokens", ["off"])])]
                },
                {
                    "file": "/etc/nginx/conf.d/app.conf",
                    "parsed": [_directive("server_tokens", ["on"])]  # Vi phạm
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/app.conf"
