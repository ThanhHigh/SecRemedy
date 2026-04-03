import os
import json
import argparse
import crossplane
import re


class NginxParser:
    def __init__(self, base_config_path):
        """
        Khởi tạo Parser với thư mục chứa cấu hình Nginx đã tải về.
        Ví dụ: base_config_path = "./tmp/nginx_raw_2221"
        """
        self.base_config_path = base_config_path
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

    # Thêm tham số -P hoặc --port (Bắt buộc)
    parser_cli.add_argument("-P", "--port", required=True,
                            help="Port của Nginx Server đã được fetch (VD: 2221, 2222)")

    # Thêm tham số -o hoặc --output (Tùy chọn, nếu không truyền sẽ tự sinh tên theo port)
    parser_cli.add_argument(
        "-o", "--output", help="Đường dẫn file JSON output (Tùy chọn)")

    # Phân tích các tham số người dùng nhập vào
    args = parser_cli.parse_args()

    # 1. Xác định thư mục đầu vào tự động dựa trên Port
    TARGET_DIR = f"./tmp/nginx_raw_{args.port}"

    # Kiểm tra xem thư mục đã được fetcher.py tải về chưa
    if not os.path.exists(TARGET_DIR):
        print(f"[LỖI] Không tìm thấy thư mục cấu hình: {TARGET_DIR}")
        print(
            f"[*] Gợi ý: Hãy chạy lệnh 'python core/fetcher.py -P {args.port}' trước để tải cấu hình về máy.")
        exit(1)

    # 2. Xác định tên file JSON đầu ra tự động dựa trên Port
    # Nếu người dùng không truyền -o, mặc định sẽ là contracts/config_ast_<port>.json
    output_contract_file = args.output if args.output else f"contracts/parser_output_{args.port}.json"

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
