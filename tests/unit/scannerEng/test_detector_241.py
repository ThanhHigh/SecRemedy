"""
Unit tests cho Detector241 — CIS Benchmark 2.4.1
"Đảm bảo NGINX chỉ lắng nghe các kết nối mạng trên các cổng được ủy quyền"

Chiến lược Kiểm thử
─────────────
• Các test evaluate() — cô lập trực tiếp logic cấp độ directive.
  Tất cả các tổ hợp giá trị listen tuân thủ / không tuân thủ đều được kiểm tra.

• Các test scan() — vận hành toàn bộ luồng duyệt AST + nhóm
  mà BaseRecom cung cấp, với các payload parser_output giả lập.

Các cổng được ủy quyền: 80, 443, 8080, 3000
"""

import pytest
from core.scannerEng.recommendations.detector_241 import Detector241


# Các fixture
@pytest.fixture
def detector():
    """Trả về một instance Detector241 mới cho mỗi test."""
    d = Detector241()
    d.authorized_ports = ["80", "443", "8080", "3000"]
    return d


def _listen_directive(args: list) -> dict:
    """Hàm hỗ trợ: tạo một dictionary directive 'listen' tối thiểu của crossplane."""
    return {"directive": "listen", "args": args}


def _server_block(listen_args_list: list) -> dict:
    """
    Hàm hỗ trợ: tạo một block 'http > server' giả lập của crossplane chứa
    một directive 'listen' cho mỗi mục trong listen_args_list.
    """
    listen_directives = [_listen_directive(args) for args in listen_args_list]
    return {
        "directive": "http",
        "args": [],
        "block": [
            {
                "directive": "server",
                "args": [],
                "block": listen_directives,
            }
        ],
    }


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
# Phần 1 — Kiểm tra tính đúng đắn của Metadata
# ──────────────────────────────────────────────────────────────────────────────

class TestMetadata:
    def test_id(self, detector):
        assert detector.id == "2.4.1"

    def test_title_contains_authorized_ports(self, detector):
        assert "authorized ports" in detector.title.lower()

    def test_authorized_ports(self, detector):
        assert "80" in detector.authorized_ports
        assert "443" in detector.authorized_ports

    def test_has_required_attributes(self, detector):
        for attr in ("description", "audit_procedure", "impact", "remediation"):
            assert getattr(detector, attr, None), f"Missing attribute: {attr}"


# ──────────────────────────────────────────────────────────────────────────────
# Phần 2 — evaluate(): các trường hợp tuân thủ (phải trả về None)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateCompliant:
    """Các directive KHÔNG NÊN kích hoạt một phát hiện không tuân thủ."""

    SERVER_CTX = ["http", "server"]
    FILEPATH = "/etc/nginx/nginx.conf"
    EXACT_PATH = ["config", 0, "parsed", 0, "block", 0, "block", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.SERVER_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Các cổng được ủy quyền (chỉ có số) ---

    def test_listen_port_80(self, detector):
        assert self._eval(detector, _listen_directive(["80"])) is None

    def test_listen_port_443_default_server(self, detector):
        assert self._eval(detector, _listen_directive(
            ["443", "default_server"])) is None

    def test_listen_port_8080(self, detector):
        assert self._eval(detector, _listen_directive(["8080"])) is None

    def test_listen_port_3000_default_server(self, detector):
        assert self._eval(detector, _listen_directive(
            ["3000", "default_server"])) is None

    # --- Các cổng được ủy quyền với từ khóa SSL/QUIC (args[0] vẫn là cổng) ---

    def test_listen_443_ssl(self, detector):
        assert self._eval(detector, _listen_directive(["443", "ssl"])) is None

    def test_listen_443_quic(self, detector):
        assert self._eval(detector, _listen_directive(["443", "quic"])) is None

    # --- Định dạng IP:port ---

    def test_listen_ip_port_80(self, detector):
        assert self._eval(detector, _listen_directive(
            ["127.0.0.1:80"])) is None

    def test_listen_ip_port_443(self, detector):
        assert self._eval(detector, _listen_directive(["0.0.0.0:443"])) is None

    def test_listen_ip_port_8080(self, detector):
        assert self._eval(detector, _listen_directive(
            ["127.0.0.1:8080"])) is None

    def test_listen_ip_port_3000_default_server(self, detector):
        assert self._eval(detector, _listen_directive(
            ["127.0.0.1:3000", "default_server"])) is None

    def test_listen_ip_port_192_443(self, detector):
        assert self._eval(detector, _listen_directive(
            ["192.168.1.10:443"])) is None

    # --- Định dạng IPv6 ---

    def test_listen_ipv6_port_80(self, detector):
        assert self._eval(detector, _listen_directive(["[::]:80"])) is None

    def test_listen_ipv6_port_443(self, detector):
        assert self._eval(detector, _listen_directive(["[::]:443"])) is None

    def test_listen_ipv6_loopback_443(self, detector):
        assert self._eval(detector, _listen_directive(["[::1]:443"])) is None

    # --- Unix socket (phải bị bỏ qua — không phải là một cổng mạng) ---

    def test_listen_unix_socket(self, detector):
        assert self._eval(detector, _listen_directive(
            ["unix:/run/nginx.sock"])) is None

    def test_listen_unix_socket_with_trailing_args(self, detector):
        assert self._eval(detector, _listen_directive(
            ["unix:/var/run/nginx.sock", "default_server"])) is None

    # --- Giá trị không phải số (VD: hostname) → Nginx mặc định là cổng 80 → tuân thủ ---

    def test_listen_hostname_treated_as_80(self, detector):
        """'listen localhost' → nginx mặc định là cổng 80 → không vi phạm."""
        assert self._eval(detector, _listen_directive(["localhost"])) is None

    def test_listen_star_treated_as_80(self, detector):
        """'listen *' → nginx mặc định là cổng 80 → không vi phạm."""
        assert self._eval(detector, _listen_directive(["*"])) is None

    # --- Tham số trống → bỏ qua một cách an toàn ---

    def test_listen_empty_args(self, detector):
        assert self._eval(detector, _listen_directive([])) is None

    # --- Không phải là directive listen → bị bỏ qua ---

    def test_non_listen_directive_server_name(self, detector):
        d = {"directive": "server_name", "args": ["example.com"]}
        assert self._eval(detector, d) is None

    def test_non_listen_directive_root(self, detector):
        d = {"directive": "root", "args": ["/var/www/html"]}
        assert self._eval(detector, d) is None

    # --- directive listen nhưng KHÔNG nằm trong một block server → bị bỏ qua ---

    def test_listen_outside_server_context_empty(self, detector):
        """Context là [], không nằm trong bất kỳ server nào."""
        result = detector.evaluate(
            _listen_directive(["443 default_server"]),
            self.FILEPATH,
            [],        # không có server trong context
            self.EXACT_PATH,
        )
        assert result is None

    def test_listen_in_events_context(self, detector):
        result = detector.evaluate(
            _listen_directive(["8080"]),
            self.FILEPATH,
            ["events"],  # server không có trong context
            self.EXACT_PATH,
        )
        assert result is None

    def test_listen_in_http_context_only(self, detector):
        """listen bên trong http nhưng KHÔNG trực tiếp nằm trong block server."""
        result = detector.evaluate(
            _listen_directive(["3000"]),
            self.FILEPATH,
            ["http"],   # không có "server" trong context
            self.EXACT_PATH,
        )
        assert result is None


# ──────────────────────────────────────────────────────────────────────────────
# Phần 3 — evaluate(): các trường hợp không tuân thủ (phải trả về các lỗi không tuân thủ)
# ──────────────────────────────────────────────────────────────────────────────

class TestEvaluateNonCompliant:
    """Các directive NÊN kích hoạt một phát hiện không tuân thủ."""

    SERVER_CTX = ["http", "server"]
    FILEPATH = "/etc/nginx/sites-enabled/app.conf"
    EXACT_PATH = ["config", 0, "parsed", 0, "block", 0, "block", 0]

    def _eval(self, detector, directive, ctx=None):
        ctx = ctx or self.SERVER_CTX
        return detector.evaluate(directive, self.FILEPATH, ctx, self.EXACT_PATH)

    # --- Các cổng không được ủy quyền thông thường ---

    def test_listen_port_8089(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        assert result is not None

    def test_listen_port_8443_default_server(self, detector):
        result = self._eval(detector, _listen_directive(
            ["8443", "default_server"]))
        assert result is not None

    def test_listen_port_3099(self, detector):
        result = self._eval(detector, _listen_directive(["3099"]))
        assert result is not None

    def test_listen_port_22(self, detector):
        result = self._eval(detector, _listen_directive(["22"]))
        assert result is not None

    def test_listen_port_9090_default_server(self, detector):
        result = self._eval(detector, _listen_directive(
            ["9090", "default_server"]))
        assert result is not None

    # --- Định dạng IP:port với cổng không được ủy quyền ---

    def test_listen_ip_port_8089(self, detector):
        result = self._eval(detector, _listen_directive(["127.0.0.1:8089"]))
        assert result is not None

    def test_listen_ip_port_3099(self, detector):
        result = self._eval(detector, _listen_directive(["192.168.0.1:3099"]))
        assert result is not None

    # --- IPv6 với cổng không được ủy quyền ---

    def test_listen_ipv6_port_8089(self, detector):
        result = self._eval(detector, _listen_directive(["[::]:8089"]))
        assert result is not None

    def test_listen_ipv6_port_9090(self, detector):
        result = self._eval(detector, _listen_directive(["[::1]:9090"]))
        assert result is not None

    # ── Kiểm tra cấu trúc payload khắc phục ──────────────────────────────────

    def test_result_contains_file(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        assert result["file"] == self.FILEPATH

    def test_result_has_remediations_list(self, detector):
        result = self._eval(detector, _listen_directive(
            ["3099", "default_server"]))
        assert isinstance(result["remediations"], list)
        assert len(result["remediations"]) == 1

    def test_remediation_action_is_delete(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        remediation = result["remediations"][0]
        assert remediation["action"] == "delete"

    def test_remediation_directive_is_listen(self, detector):
        result = self._eval(detector, _listen_directive(
            ["3099", "default_server"]))
        remediation = result["remediations"][0]
        assert remediation["directive"] == "listen"

    def test_remediation_context_matches_exact_path(self, detector):
        result = self._eval(detector, _listen_directive(["8089"]))
        remediation = result["remediations"][0]
        assert remediation["context"] == self.EXACT_PATH

    def test_remediation_context_is_exact_path_reference(self, detector):
        """exact_path được truyền vào phải được giữ nguyên chính xác (theo tham chiếu hoặc giá trị)."""
        custom_path = ["config", 2, "parsed", 7, "block", 3, "block", 1]
        result = detector.evaluate(
            _listen_directive(["8089"]),
            self.FILEPATH,
            self.SERVER_CTX,
            custom_path,
        )
        assert result["remediations"][0]["context"] == custom_path


# ──────────────────────────────────────────────────────────────────────────────
# Phần 4 — scan(): các test cho toàn bộ luồng
# ──────────────────────────────────────────────────────────────────────────────

class TestScan:
    """Các test tích hợp vận hành BaseRecom.scan() → _traverse_ast() → evaluate()."""

    # --- Các cấu hình tuân thủ hoàn toàn sẽ không sinh ra phát hiện nào ---

    def test_all_compliant_ports_returns_empty(self, detector):
        parser_output = _make_parser_output([
            _server_block([["80"], ["443", "ssl"], ["8080"],
                          ["3000", "default_server"]])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_empty_config_list_returns_empty(self, detector):
        findings = detector.scan({"config": []})
        assert findings == []

    def test_unix_socket_only_returns_empty(self, detector):
        parser_output = _make_parser_output([
            _server_block([["unix:/run/nginx.sock"]])
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_non_conf_file_skipped(self, detector):
        """Các file không kết thúc bằng .conf phải bị BaseRecom.scan() bỏ qua."""
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/nginx",     # không có đuôi .conf
                    "parsed": [_server_block([["8080"]])]
                }
            ]
        }
        findings = detector.scan(parser_output)
        assert findings == []

    # --- Một vi phạm duy nhất ---

    def test_single_unauthorized_port_detected(self, detector):
        parser_output = _make_parser_output([
            _server_block([["8089"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    def test_single_violation_file_path_correct(self, detector):
        path = "/etc/nginx/sites-enabled/test.conf"
        parser_output = _make_parser_output(
            [_server_block([["3099"]])], filepath=path)
        findings = detector.scan(parser_output)
        assert findings[0]["file"] == path

    def test_single_violation_action_is_delete(self, detector):
        parser_output = _make_parser_output(
            [_server_block([["8089", "default_server"]])])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["action"] == "delete"

    def test_single_violation_directive_is_listen(self, detector):
        parser_output = _make_parser_output(
            [_server_block([["3099", "default_server"]])])
        findings = detector.scan(parser_output)
        assert findings[0]["remediations"][0]["directive"] == "listen"

    # --- Nhiều vi phạm trong một block server được nhóm vào một mục file ---

    def test_two_violations_same_file_grouped(self, detector):
        parser_output = _make_parser_output([
            _server_block([["8089"], ["3099", "default_server"]])
        ])
        findings = detector.scan(parser_output)
        # Chỉ có một mục file (nhóm theo file)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    def test_three_violations_same_file_grouped(self, detector):
        parser_output = _make_parser_output([
            _server_block([["8089"], ["3099", "default_server"], ["8433"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 3

    # --- Trộn lẫn tuân thủ + không tuân thủ trong cùng một block ---

    def test_mixed_listen_only_unauthorized_flagged(self, detector):
        """80 là OK, 443 là OK, 8089 sẽ là vi phạm duy nhất."""
        parser_output = _make_parser_output([
            _server_block([["80"], ["443", "ssl"], ["8089"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 1

    def test_mixed_listen_only_authorized_unflagged(self, detector):
        """8080 là OK, 8089 và 3099 sẽ bị đánh dấu."""
        parser_output = _make_parser_output([
            _server_block([["8080"], ["8089"], ["3099", "default_server"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert len(findings[0]["remediations"]) == 2

    # --- Nhiều file (nhiều mục cấu hình) ---

    def test_violations_across_two_files(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/conf.d/app1.conf",
                    "parsed": [_server_block([["8089"]])],
                },
                {
                    "file": "/etc/nginx/conf.d/app2.conf",
                    "parsed": [_server_block([["3099"]])],
                },
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 2
        files = {f["file"] for f in findings}
        assert "/etc/nginx/conf.d/app1.conf" in files
        assert "/etc/nginx/conf.d/app2.conf" in files
        assert len(findings[0]["remediations"]) == 1
        assert len(findings[1]["remediations"]) == 1

    def test_one_clean_file_one_dirty_file(self, detector):
        parser_output = {
            "config": [
                {
                    "file": "/etc/nginx/conf.d/clean.conf",
                    "parsed": [_server_block([["80"], ["443", "ssl"]])],
                },
                {
                    "file": "/etc/nginx/conf.d/dirty.conf",
                    "parsed": [_server_block([["8089", "default_server"]])],
                },
            ]
        }
        findings = detector.scan(parser_output)
        assert len(findings) == 1
        assert findings[0]["file"] == "/etc/nginx/conf.d/dirty.conf"
        assert len(findings[0]["remediations"]) == 1

    # --- directive listen trong context không phải server không được tạo ra dương tính giả ---

    def test_listen_in_http_context_not_flagged(self, detector):
        """Một directive 'listen' nằm trực tiếp trong 'http' (không phải server) phải bị bỏ qua."""
        parser_output = _make_parser_output([
            {
                "directive": "http",
                "args": [],
                "block": [
                    # listen ở cấp http (không được bọc bởi server)
                    {"directive": "listen", "args": ["8089"]},
                ],
            }
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_listen_in_events_context_not_flagged(self, detector):
        """Một directive 'listen' nằm trong 'events' (không phải server) phải bị bỏ qua."""
        parser_output = _make_parser_output([
            {
                "directive": "events",
                "args": [],
                "block": [
                    {"directive": "listen", "args": ["8089"]},
                ],
            }
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    def test_listen_at_top_level_not_flagged(self, detector):
        """Một directive 'listen' nằm ở cấp cao nhất (không nằm trong bất kỳ block nào) phải bị bỏ qua."""
        parser_output = _make_parser_output([
            {"directive": "listen", "args": ["8089"]},
        ])
        findings = detector.scan(parser_output)
        assert findings == []

    # --- cổng không được ủy quyền IPv6 qua scan ---

    def test_ipv6_unauthorized_port_via_scan(self, detector):
        parser_output = _make_parser_output([
            _server_block([["[::]:3099"]])
        ])
        findings = detector.scan(parser_output)
        assert len(findings) == 1

    # --- Tính hoàn thiện của schema kết quả ---

    def test_scan_result_keys(self, detector):
        parser_output = _make_parser_output([_server_block([["8089"]])])
        findings = detector.scan(parser_output)
        result = findings[0]
        assert "file" in result
        assert "remediations" in result

    def test_scan_remediation_keys(self, detector):
        parser_output = _make_parser_output([_server_block([["3099"]])])
        findings = detector.scan(parser_output)
        remediation = findings[0]["remediations"][0]
        assert "action" in remediation
        assert "directive" in remediation
        assert "context" in remediation
