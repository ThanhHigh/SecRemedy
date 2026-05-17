import os
import json
import argparse
import crossplane
import re


class NginxParser:
    def __init__(self, base_config_path, remote_dir='/etc/nginx', log_file=None):
        """
        Khởi tạo Parser với thư mục chứa cấu hình Nginx đã tải về.
        Ví dụ: base_config_path = "./tmp/nginx_raw_2221"
        """
        self.base_config_path = base_config_path
        self.remote_dir = remote_dir
        # Đường dẫn tới file nginx.conf chính sau khi giải nén
        self.main_conf_path = os.path.join(self.base_config_path, "nginx.conf")
        self.log_file = log_file

    def log(self, msg):
        if self.log_file:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

    def normalize_includes(self):
        """
        Quét toàn bộ các file .conf đã tải về.
        Sử dụng regex để chuyển đổi các đường dẫn
        include tuyệt đối (VD: include /etc/nginx/conf.d/*.conf;)
        thành đường dẫn tương đối (VD: include conf.d/*.conf;).
        """
        if not os.path.exists(self.base_config_path):
            return

        self.log("[*] Đang tiền xử lý (Pre-processing) để chuẩn hóa đường dẫn include...")

        # Giải thích Regex:
        # (include\s+) : Group 1 - Bắt chữ 'include' và toàn bộ khoảng trắng/tab/newline theo sau nó.
        # (["']?)      : Group 2 - Bắt dấu ngoặc kép (") hoặc ngoặc đơn (') nếu có (optional).
        # /etc/nginx/  : Chuỗi cần loại bỏ.
        pattern = re.compile(r'(include\s+)(["\']?)/etc/nginx/')

        for root, dirs, files in os.walk(self.base_config_path):
            for file in files:
                if file.endswith(".conf"):
                    file_path = os.path.join(root, file)

                    # Đọc nội dung file
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()

                    # Nếu phát hiện pattern, tiến hành thay thế
                    if pattern.search(content):
                        # Thay thế bằng Group 1 và Group 2, bỏ đi phần /etc/nginx/
                        # \g<1> giữ lại đúng số lượng khoảng trắng gốc
                        # \g<2> giữ lại dấu ngoặc (nếu có)
                        new_content = pattern.sub(r'\g<1>\g<2>', content)

                        # Ghi đè lại file tạm
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(new_content)
                        self.log(f"  -> Đã chuẩn hóa include trong file: {file}")

    def parse(self):
        """
        Sử dụng crossplane để phân tích đệ quy toàn bộ cấu hình.
        """
        if not os.path.exists(self.main_conf_path):
            raise FileNotFoundError(
                f"[LỖI] Không tìm thấy file cấu hình chính tại: {self.main_conf_path}")

        self.normalize_includes()

        self.log(f"[*] Đang phân tích cú pháp (AST) cho: {self.main_conf_path}")

        # Gọi API của crossplane. catch_errors=True giúp tool không bị crash nếu thiếu file include
        payload = crossplane.parse(self.main_conf_path, catch_errors=True)

        # Kiểm tra xem crossplane có gặp lỗi khi parse include không
        if payload.get("status") == "failed" or payload.get("errors"):
            self.log(
                "[CẢNH BÁO] Crossplane gặp lỗi (Thường do sai đường dẫn include tuyệt đối):")
            for err in payload.get("errors", []):
                self.log(f"  -> {err['error']}")

        # Thay thế đường dẫn local thành remote trong kết quả trả về
        base_path_to_replace = os.path.abspath(self.base_config_path)
        if not base_path_to_replace.endswith(os.sep):
            base_path_to_replace += os.sep

        if "config" in payload:
            for config_item in payload["config"]:
                local_file = config_item.get("file", "")
                if local_file:
                    # Convert to absolute to ensure proper matching
                    abs_local_file = os.path.abspath(local_file)
                    if abs_local_file.startswith(base_path_to_replace):
                        rel_path = abs_local_file[len(base_path_to_replace):]
                        remote_file = os.path.join(self.remote_dir, rel_path)
                        # Fix path separators for Windows/Linux
                        remote_file = remote_file.replace('\\', '/')
                        config_item["file"] = remote_file
                    elif local_file.startswith(self.base_config_path):
                        # Fallback if abspath logic fails
                        rel_path = local_file[len(self.base_config_path):]
                        if rel_path.startswith('/') or rel_path.startswith('\\'):
                            rel_path = rel_path[1:]
                        remote_file = os.path.join(self.remote_dir, rel_path)
                        remote_file = remote_file.replace('\\', '/')
                        config_item["file"] = remote_file

        return payload

    def export_to_contract(self, output_file):
        """
        Lưu kết quả AST ra file JSON để Thành viên 2 (Remediation) sử dụng.
        """
        payload = self.parse()

        # Đảm bảo thư mục contracts tồn tại
        os.makedirs(os.path.dirname(output_file), exist_ok=True)

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)

        self.log(f"[THÀNH CÔNG] Đã xuất Data Contract (AST) ra file: {output_file}")
        return payload


RAW_CONFIGS_DIR = "./tmp/raw_configs"
HARDENED_CONFIGS_DIR = "./tmp/hardened_configs"

PHASE_PATHS = {
    "before": {
        "raw_dir": RAW_CONFIGS_DIR,
        "parser_output_dir": "tmp/contracts/parsers_output",
        "parser_report_dir": "./tmp/contracts/parsers_report",
    },
    "after": {
        "raw_dir": HARDENED_CONFIGS_DIR,
        "parser_output_dir": "tmp/contracts/parsers_output_after",
        "parser_report_dir": "./tmp/contracts/parsers_report_after",
    },
}


def _discover_servers_from_raw_configs(raw_dir=RAW_CONFIGS_DIR):
    """Tự động lấy danh sách port từ tên các thư mục con của <raw_dir>/."""
    if not os.path.isdir(raw_dir):
        return []
    ports = []
    for name in sorted(os.listdir(raw_dir)):
        full = os.path.join(raw_dir, name)
        if os.path.isdir(full) and name.isdigit():
            ports.append(int(name))
    return [{"port": p} for p in ports]


def main():
    parser_cli = argparse.ArgumentParser(
        description="Nginx Configuration AST Parser (Crossplane Wrapper)"
    )
    parser_cli.add_argument(
        "--config", "-c",
        default=None,
        help="Path to config file. Nếu bỏ trống: tự động quét toàn bộ <raw_dir>/<port>/."
    )
    parser_cli.add_argument(
        "--phase",
        choices=["before", "after"],
        default="before",
        help="'before' đọc tmp/raw_configs/, 'after' đọc tmp/hardened_configs/. "
             "Đồng thời quyết định nơi ghi parser_output (after → suffix _after)."
    )
    args = parser_cli.parse_args()

    paths = PHASE_PATHS[args.phase]
    raw_dir = paths["raw_dir"]
    parser_output_dir = paths["parser_output_dir"]
    report_dir = paths["parser_report_dir"]

    config_path = args.config
    if config_path:
        if not os.path.exists(config_path):
            print(f"[-] Lỗi: Không tìm thấy file cấu hình {config_path}")
            exit(1)
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"[-] Lỗi cú pháp JSON trong file {config_path}: {e}")
            exit(1)
        servers = config_data.get("servers", [])
        if not servers:
            print(f"[-] Không có server nào được định nghĩa trong {config_path}")
            exit(1)
    else:
        servers = _discover_servers_from_raw_configs(raw_dir)
        if not servers:
            print(f"[-] Không có raw config nào dưới {raw_dir}. "
                  f"Hãy chạy 'tests/run_tests.sh' trước, hoặc cung cấp --config.")
            exit(1)
        print(f"[*] [phase={args.phase}] Auto-discovered {len(servers)} port(s) từ {raw_dir}.")

    os.makedirs(report_dir, exist_ok=True)

    for server in servers:
        current_port = server.get("port")
        if not current_port:
            continue

        report_file = os.path.join(report_dir, f"parser_report_{current_port}.md")
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"# Parser Report - Port {current_port} ({args.phase})\n\n```text\n")

        # 1. Xác định thư mục đầu vào tự động dựa trên Port (raw configs đã copy bởi run_tests.sh)
        TARGET_DIR = f"{raw_dir}/{current_port}"

        # Kiểm tra xem thư mục raw configs đã sẵn sàng chưa
        if not os.path.exists(TARGET_DIR):
            with open(report_file, "a", encoding="utf-8") as f:
                f.write(f"[LỖI] Không tìm thấy thư mục cấu hình: {TARGET_DIR}\n")
                f.write(f"[*] Gợi ý: Hãy chạy 'bash tests/run_tests.sh' để chuẩn bị {raw_dir}/<port>/.\n")
                f.write("```\n")
            continue

        # 2. Xác định tên file JSON đầu ra tự động dựa trên config (đóng vai trò là input_path của scanner)
        output_contract_file = server.get(
            "input_path", f"{parser_output_dir}/parser_output_{current_port}.json")

        # 3. Thực thi Parser
        nginx_parser = NginxParser(base_config_path=TARGET_DIR, log_file=report_file)
        try:
            ast_data = nginx_parser.export_to_contract(
                output_file=output_contract_file)

            # In thống kê cơ bản
            parsed_files = len(ast_data.get("config", []))
            nginx_parser.log(f"[*] Tổng số file cấu hình đã phân tích thành công: {parsed_files}")

        except Exception as e:
            nginx_parser.log(f"[LỖI HỆ THỐNG] {e}")

        with open(report_file, "a", encoding="utf-8") as f:
            f.write("```\n")


# --- Khối xử lý CLI Arguments ---
if __name__ == "__main__":
    main()
