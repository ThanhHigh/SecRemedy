import os
import json
import argparse
import crossplane
import re


class NginxParser:
    def __init__(self, base_config_path, remote_dir='/etc/nginx'):
        """
        Khởi tạo Parser với thư mục chứa cấu hình Nginx đã tải về.
        Ví dụ: base_config_path = "./tmp/nginx_raw_2221"
        """
        self.base_config_path = base_config_path
        self.remote_dir = remote_dir
        # Đường dẫn tới file nginx.conf chính sau khi giải nén
        self.main_conf_path = os.path.join(self.base_config_path, "nginx.conf")

    def normalize_includes(self):
        """
        Quét toàn bộ các file .conf đã tải về.
        Sử dụng regex để chuyển đổi các đường dẫn 
        include tuyệt đối (VD: include /etc/nginx/conf.d/*.conf;) 
        thành đường dẫn tương đối (VD: include conf.d/*.conf;).
        """
        if not os.path.exists(self.base_config_path):
            return

        print("[*] Đang tiền xử lý (Pre-processing) để chuẩn hóa đường dẫn include...")

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
                        print(f"  -> Đã chuẩn hóa include trong file: {file}")

    def parse(self):
        """
        Sử dụng crossplane để phân tích đệ quy toàn bộ cấu hình.
        """
        if not os.path.exists(self.main_conf_path):
            raise FileNotFoundError(
                f"[LỖI] Không tìm thấy file cấu hình chính tại: {self.main_conf_path}")

        self.normalize_includes()

        print(f"[*] Đang phân tích cú pháp (AST) cho: {self.main_conf_path}")

        # Gọi API của crossplane. catch_errors=True giúp tool không bị crash nếu thiếu file include
        payload = crossplane.parse(self.main_conf_path, catch_errors=True)

        # Kiểm tra xem crossplane có gặp lỗi khi parse include không
        if payload.get("status") == "failed" or payload.get("errors"):
            print(
                "[CẢNH BÁO] Crossplane gặp lỗi (Thường do sai đường dẫn include tuyệt đối):")
            for err in payload.get("errors", []):
                print(f"  -> {err['error']}")

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

        print(
            f"[THÀNH CÔNG] Đã xuất Data Contract (AST) ra file: {output_file}")
        return payload


# --- Khối xử lý CLI Arguments ---
if __name__ == "__main__":
    # Khởi tạo ArgumentParser
    parser_cli = argparse.ArgumentParser(
        description="Nginx Configuration AST Parser (Crossplane Wrapper)")

    # Thêm tham số -P hoặc --port
    parser_cli.add_argument("-P", "--port", type=int,
                            help="Port của Nginx Server đã được fetch (VD: 2221, 2222)")

    parser_cli.add_argument("-a", "--all-ports", action="store_true",
                            help="Phân tích trên tất cả các port định nghĩa trong docker-compose.yml")

    # Thêm tham số -o hoặc --output (Tùy chọn, nếu không truyền sẽ tự sinh tên theo port)
    parser_cli.add_argument(
        "-o", "--output", help="Đường dẫn file JSON output (Tùy chọn)")

    # Phân tích các tham số người dùng nhập vào
    args = parser_cli.parse_args()

    if args.all_ports:
        target_ports = []
        try:
            with open("tests/integration/docker-compose.yml", "r") as f:
                content = f.read()
                # Find all mappings to port 22, e.g., "2221:22"
                matches = re.findall(r'"(\d+):22"', content)
                target_ports = [int(m) for m in matches]
        except Exception as e:
            print(f"[-] Lỗi đọc docker-compose.yml: {e}")
            exit(1)
        if not target_ports:
             print("[-] Không tìm thấy port SSH nào trong docker-compose.yml")
             exit(1)
    elif args.port:
        target_ports = [args.port]
    else:
        parser_cli.error("Bạn phải cung cấp -P/--port hoặc dùng cờ -a/--all-ports.")

    for current_port in target_ports:
        print(f"\n==========================================")
        print(f"[*] BẮT ĐẦU PARSE PORT {current_port}")
        print(f"==========================================")
        # 1. Xác định thư mục đầu vào tự động dựa trên Port
        TARGET_DIR = f"./tmp/nginx_raw_{current_port}"

        # Kiểm tra xem thư mục đã được fetcher.py tải về chưa
        if not os.path.exists(TARGET_DIR):
            print(f"[LỖI] Không tìm thấy thư mục cấu hình: {TARGET_DIR}")
            print(f"[*] Gợi ý: Hãy chạy lệnh 'python core/scannerEng/fetcher.py -P {current_port}' trước để tải cấu hình về máy.")
            continue

        # 2. Xác định tên file JSON đầu ra tự động dựa trên Port
        # Nếu người dùng không truyền -o, mặc định sẽ là contracts/config_ast_<port>.json
        output_contract_file = args.output if (args.output and not args.all_ports) else f"contracts/parser_output_{current_port}.json"

        # 3. Thực thi Parser
        nginx_parser = NginxParser(base_config_path=TARGET_DIR)
        try:
            ast_data = nginx_parser.export_to_contract(
                output_file=output_contract_file)

            # In thống kê cơ bản
            parsed_files = len(ast_data.get("config", []))
            print(
                f"[*] Tổng số file cấu hình đã phân tích thành công: {parsed_files}")

        except Exception as e:
            print(f"[LỖI HỆ THỐNG] {e}")
