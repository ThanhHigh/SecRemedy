from typing import Dict, List, Any, Optional
from core.scannerEng.base_recom import BaseRecom
from core.recom_registry import RecomID


class Detector242(BaseRecom):
    def __init__(self):
        super().__init__(RecomID.CIS_2_4_2)

    def _should_skip_block(self, node: Dict[str, Any]) -> bool:
        if not isinstance(node, dict):
            return False
        if node.get("directive") != "server":
            return False

        block = node.get("block", [])
        has_https_redirect = False
        has_catch_all_server_name = False

        for child in block:
            if not isinstance(child, dict):
                continue
            dir_name = child.get("directive")
            args = child.get("args", [])

            if dir_name == "server_name" and len(args) == 1 and args[0] == "_":
                has_catch_all_server_name = True
            elif dir_name == "return" and len(args) >= 2 and args[0] in ("301", "302", "307", "308") and args[1].startswith("https://"):
                has_https_redirect = True

        return has_https_redirect and not has_catch_all_server_name

    def _check_return(self, block: List[Dict[str, Any]], in_if: bool = False) -> bool:
        for d in block:
            if d.get("directive") == "return":
                if not in_if and d.get("args"):
                    status = str(d["args"][0])
                    if status.startswith("4"):
                        return True
            elif d.get("directive") == "if":
                if self._check_return(d.get("block", []), in_if=True):
                    pass
            elif d.get("directive") == "location" and d.get("args") == ["/"]:
                if self._check_return(d.get("block", []), in_if=in_if):
                    return True
        return False

    def scan(self, parser_output: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Hàm chính được gọi bởi Scanner Engine.
        Nhận vào toàn bộ AST của các file cấu hình và trả về danh sách các uncompliances.
        Kết quả được gộp theo file (mỗi file 1 entry) để khớp với JSON Contract.
        """
        uncompliances = []

        used_protocols = set()
        valid_protocols = set()

        http_file = None
        http_path = None
        http_block_len = 0

        # Mặc định file đầu tiên là file cần sửa nếu không tìm thấy http block
        first_file = None

        remediation_block = []

        remediation_block.append(
            {"directive": "listen", "args": ["80", "default_server"]})
        remediation_block.append(
            {"directive": "listen", "args": ["[::]:80", "default_server"]})
        remediation_block.append({"directive": "listen", "args": [
                                  "443", "ssl", "default_server"]})
        remediation_block.append({"directive": "listen", "args": [
                                  "[::]:443", "ssl", "default_server"]})
        remediation_block.append({"directive": "listen", "args": [
                                  "443", "quic", "default_server"]})
        remediation_block.append({"directive": "listen", "args": [
                                  "[::]:443", "quic", "default_server"]})
        remediation_block.append(
            {"directive": "ssl_reject_handshake", "args": ["on"]})
        remediation_block.append(
            {"directive": "server_name", "args": ["_"]})
        remediation_block.append({"directive": "return", "args": ["444"]})

        has_replace_rem = False

        for config_idx, config_file in enumerate(parser_output.get("config", [])):
            filepath = config_file.get("file", "")

            # Chỉ xử lý các file có đuôi .conf
            if not filepath.endswith(".conf"):
                continue

            if not first_file:
                first_file = filepath

            parsed_ast = config_file.get("parsed", [])

            base_exact_path = ["config", config_idx, "parsed"]

            for dir_idx, directive in enumerate(parsed_ast):
                line = directive.get("line", 0)

                if directive.get("directive") == "http":
                    http_file = filepath
                    http_path = base_exact_path + [dir_idx, "block"]
                    http_block = directive.get("block", [])
                    http_block_len = len(http_block)

                    for http_dir_idx, http_dir in enumerate(http_block):
                        line = http_dir.get("line", 0)

                        if http_dir.get("directive") == "server":
                            if self._should_skip_block(http_dir):
                                continue

                            server_block = http_dir.get("block", [])
                            protocols_with_default = set()
                            current_block_protocols = set()
                            has_valid_return = self._check_return(server_block)
                            has_ssl_reject = False

                            for s_dir in server_block:
                                if s_dir.get("directive") == "listen":
                                    args = s_dir.get("args", [])
                                    is_ssl = "ssl" in args
                                    is_quic = "quic" in args
                                    is_default = "default_server" in args

                                    addr = str(args[0]) if args else ""
                                    is_ipv6 = "[::]" in addr

                                    base_p = "http"
                                    if is_quic:
                                        base_p = "quic"
                                    elif is_ssl:
                                        base_p = "https"

                                    p = f"ipv6_{base_p}" if is_ipv6 else f"ipv4_{base_p}"

                                    used_protocols.add(p)
                                    current_block_protocols.add(p)
                                    if is_default:
                                        protocols_with_default.add(p)

                                elif s_dir.get("directive") == "ssl_reject_handshake":
                                    if s_dir.get("args") and s_dir["args"][0] == "on":
                                        has_ssl_reject = True

                            is_valid_block = True
                            for p in protocols_with_default:
                                if "http" in p and has_valid_return:
                                    valid_protocols.add(p)
                                elif "https" in p and has_valid_return and has_ssl_reject:
                                    valid_protocols.add(p)
                                elif "quic" in p and has_valid_return:
                                    valid_protocols.add(p)
                                else:
                                    is_valid_block = False

                            if protocols_with_default and current_block_protocols - protocols_with_default:
                                is_valid_block = False

                            if protocols_with_default and not is_valid_block:
                                has_replace_rem = True
                                uncompliances.append({
                                    "file": filepath,
                                    "remediations": [{
                                        "action": "replace",
                                        "directive": "server",
                                        "line": line,
                                        "args": [],
                                        "block": remediation_block,
                                        "logical_context": ["http"],
                                        "exact_path": http_path + [http_dir_idx]
                                    }]
                                })

                elif directive.get("directive") == "server":
                    if self._should_skip_block(directive):
                        continue

                    server_block = directive.get("block", [])
                    protocols_with_default = set()
                    current_block_protocols = set()
                    has_valid_return = self._check_return(server_block)
                    has_ssl_reject = False

                    for s_dir in server_block:
                        if s_dir.get("directive") == "listen":
                            args = s_dir.get("args", [])
                            is_ssl = "ssl" in args
                            is_quic = "quic" in args
                            is_default = "default_server" in args

                            addr = str(args[0]) if args else ""
                            is_ipv6 = "[::]" in addr

                            base_p = "http"
                            if is_quic:
                                base_p = "quic"
                            elif is_ssl:
                                base_p = "https"

                            p = f"ipv6_{base_p}" if is_ipv6 else f"ipv4_{base_p}"

                            used_protocols.add(p)
                            current_block_protocols.add(p)
                            if is_default:
                                protocols_with_default.add(p)

                        elif s_dir.get("directive") == "ssl_reject_handshake":
                            if s_dir.get("args") and s_dir["args"][0] == "on":
                                has_ssl_reject = True

                    is_valid_block = True
                    for p in protocols_with_default:
                        if "http" in p and has_valid_return:
                            valid_protocols.add(p)
                        elif "https" in p and has_valid_return and has_ssl_reject:
                            valid_protocols.add(p)
                        elif "quic" in p and has_valid_return:
                            valid_protocols.add(p)
                        else:
                            is_valid_block = False

                    if protocols_with_default and current_block_protocols - protocols_with_default:
                        is_valid_block = False

                    if protocols_with_default and not is_valid_block:
                        has_replace_rem = True
                        uncompliances.append({
                            "file": filepath,
                            "remediations": [{
                                "action": "replace",
                                "directive": "server",
                                "line": line,
                                "args": [],
                                "block": remediation_block,
                                "logical_context": ["http"],
                                "exact_path": base_exact_path + [dir_idx]
                            }]
                        })

        if not used_protocols:
            used_protocols.add("ipv4_http")

        missing_protocols = used_protocols - valid_protocols

        if missing_protocols and not has_replace_rem:
            rem_entry = {
                "action": "add",
                "directive": "server",
                "line": line,
                "args": [],
                "block": remediation_block,
                "logical_context": ["http"],
                "exact_path": http_path + [http_block_len] if http_path else ["config", 0, "parsed", http_block_len]
            }

            if http_file and http_path:
                rem_entry["exact_path"] = http_path + [http_block_len]
                uncompliances.append({
                    "file": http_file,
                    "remediations": [rem_entry]
                })
            else:
                uncompliances.append({
                    "file": first_file or "unknown.conf",
                    "remediations": [rem_entry]
                })

        result = self._group_by_file(uncompliances)
        return result
