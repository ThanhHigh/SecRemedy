import json
import os
from typing import List, Dict, Any
import argparse

from paths import ROOT_DIR
from ast_locator import locate_blocks, extract_main_parsed_ast


def build_default_output_path(input_path: str) -> str:
    input_filename = os.path.basename(input_path)
    base_name, ext = os.path.splitext(input_filename)
    output_filename = f"{base_name}_modified{ext if ext else '.json'}"
    os.makedirs(os.path.join(ROOT_DIR, "tmp", "ast_modified"), exist_ok=True)
    return os.path.join(ROOT_DIR, "tmp", "ast_modified", output_filename)

def inject_remediations(parsed_ast: List[Dict[str, Any]], failed_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Hàm tự động vá lỗi bằng cách chèn/cập nhật cấu hình an toàn vào cây AST.
    
    Args:
        parsed_ast (List[Dict]): Cây AST của Nginx (mảng 'parsed').
        failed_rules (List[Dict]): Danh sách các lỗi lấy từ Database (bảng FailedRule).
        
    Returns:
        List[Dict]: Cây AST đã được chỉnh sửa (Modified AST).
    """
    for rule in failed_rules:
        context_path = rule.get("target_context", [])
        recommended = rule.get("recommended_directive", {})
        
        if not context_path or not recommended:
            continue
            
        directive_name = recommended.get("directive")
        recommended_args = recommended.get("args", [])
        
        # 1. Tìm tất cả các block khớp với context_path (VD: ["http", "server"])
        target_blocks = locate_blocks(parsed_ast, context_path)
        
        for block in target_blocks:
            # 2. Kiểm tra xem directive này đã tồn tại trong block chưa
            existing_directive = None
            
            # Xử lý trường hợp đặc biệt: add_header (Vì Nginx cho phép nhiều add_header)
            if directive_name == "add_header" and len(recommended_args) > 0:
                header_name = recommended_args[0] # VD: "X-Frame-Options"
                existing_directive = next(
                    (d for d in block if d.get("directive") == "add_header" 
                     and len(d.get("args", [])) > 0 
                     and d["args"][0] == header_name), 
                    None
                )
            else:
                # Các directive thông thường (chỉ được xuất hiện 1 lần trong block, VD: server_tokens, ssl_protocols)
                existing_directive = next(
                    (d for d in block if d.get("directive") == directive_name), 
                    None
                )
            
            # 3. Thực hiện Vá lỗi (Remediate)
            if existing_directive:
                # NẾU ĐÃ TỒN TẠI -> Cập nhật lại tham số (Update args)
                # VD: Đổi ["TLSv1", "TLSv1.1"] thành ["TLSv1.2", "TLSv1.3"]
                existing_directive["args"] = recommended_args
            else:
                # NẾU CHƯA TỒN TẠI -> Thêm mới vào cuối block (Append)
                new_directive = {
                    "directive": directive_name,
                    "args": recommended_args
                }
                block.append(new_directive)
                
    # Vì parsed_ast được truyền theo dạng tham chiếu (reference), 
    # các thay đổi trên 'block' đã trực tiếp làm thay đổi 'parsed_ast'.
    return parsed_ast

# ==========================================
# KHỐI TEST (Chỉ chạy khi chạy trực tiếp file này)
# ==========================================
if __name__ == "__main__":

    # Khoi tao ArgumentParser
    parser_cli = argparse.ArgumentParser(description="Remediation Injector for Nginx AST")
        # Hướng dẫn sử dụng CLI:
        # Sử dụng: python injector.py -h
        # Hiển thị chi tiết các tham số CLI

    # Them tham so -i hoac --input de chi dinh duong dan file AST goc {contracts/config_ast.json}
    parser_cli.add_argument(
        "-i", 
        "--input", 
        required=True, 
        help="Require - File JSON input original AST"
    )

    # Them tham so -o hoac --output de chi dinh duong dan file AST sau khi da inject
    parser_cli.add_argument(
        "-o",
        "--output",
        help="Not Require - File JSON output modified AST sau khi inject. Default: tmp/ast_modified/<ten_input>_modified.json"
    )
        # Thêm ví dụ sử dụng vào help
    parser_cli.epilog = "Ví dụ: python injector.py -i contracts/config_ast_2221.json -o tmp/ast_modified/config_ast_2221_modified.json"


    # Phan tich cac tham so nguoi dung nhap vao
    args = parser_cli.parse_args()

    # Trich xuat duong dan den file AST goc
    input_path = args.input
    output_path = args.output if args.output else build_default_output_path(input_path)

    # # Test Debug
    # input_path = "contracts/config_ast_2221.json"

    config_ast_path = os.path.join(os.getcwd(), input_path)
    output_path = os.path.join(os.getcwd(), output_path)
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    # Thuc thi Injector dua tren file AST duoc chi dinh
    
    # 1. Đọc file AST
    # Nếu người dùng nhập đường dẫn tương đối, chuyển thành đường dẫn tuyệt đối
    # if not os.path.isabs(config_ast_path):
    #     current_dir = os.path.dirname(os.path.abspath(__file__))
    #     project_root = os.path.dirname(os.path.dirname(current_dir))
    #     config_ast_path = os.path.join(project_root, config_ast_path)
    
    # # Chuyển về đường dẫn chuẩn (normalize)
    # config_ast_path = os.path.abspath(config_ast_path)
    
    try:
        with open(config_ast_path, "r") as f:
            raw_data = json.load(f)
            main_ast = extract_main_parsed_ast(raw_data)
            # print(main_ast)
    except FileNotFoundError:
        print(f"[-] Không tìm thấy file config_ast.json tại {config_ast_path}.")
        exit(1)

    # 2. Giả lập dữ liệu FailedRules trả về từ Database (Do TV1 quét ra)
    mock_failed_rules = [
        {
            "rule_id": "CIS_2.1.3",
            "rule_name": "Ensure server_tokens directive is set to off",
            "severity": "High",
            "target_context": ["http"],
            "recommended_directive": {"directive": "server_tokens", "args": ["off"]}
        },
        {
            "rule_id": "CIS_5.1.3",
            "rule_name": "Ensure X-Frame-Options header is configured",
            "severity": "Medium",
            "target_context": ["http", "server"],
            "recommended_directive": {"directive": "add_header", "args": ["X-Frame-Options", "SAMEORIGIN"]}
        },
        {
            "rule_id": "CIS_3.1",
            "rule_name": "Ensure outdated SSL protocols are disabled",
            "severity": "Medium",
            "target_context": ["http", "server"], 
            # Chú ý: Trong file gốc đang là TLSv1 TLSv1.1 TLSv1.2 -> Tool phải tự động ghi đè thành TLSv1.2 TLSv1.3
            "recommended_directive": {"directive": "ssl_protocols", "args": ["TLSv1.2", "TLSv1.3"]}
        }
    ]

    # print("[*] Đang tiến hành Inject cấu hình an toàn vào AST...")
    modified_ast = inject_remediations(main_ast, mock_failed_rules)

    
    with open(output_path, "w") as f_out:
        json.dump(modified_ast, f_out, indent=2, ensure_ascii=False)
    print(f"[+] Modified AST exported to {output_path}")
    
    # # 3. In ra kết quả để kiểm chứng
    # print("\n[+] KẾT QUẢ SAU KHI INJECT:")
    
    # # Kiểm tra block HTTP (Xem có server_tokens và add_header chưa)
    # http_block = locate_blocks(modified_ast, ["http"])[0]
    # print("\n--- Các directive mới trong block 'http' ---")
    # for d in http_block:
    #     if d.get("directive") in ["server_tokens", "add_header"]:
    #         print(f"    {d['directive']} {' '.join(d['args'])};")
            
    # # Kiểm tra block Server (Xem ssl_protocols đã bị ghi đè chưa)
    # server_blocks = locate_blocks(modified_ast, ["http", "server"])
    # print("\n--- Kiểm tra ghi đè 'ssl_protocols' trong các block 'server' ---")
    # for idx, s_block in enumerate(server_blocks):
    #     ssl_dir = next((d for d in s_block if d.get("directive") == "ssl_protocols"), None)
    #     if ssl_dir:
    #         print(f"    Server {idx + 1}: ssl_protocols {' '.join(ssl_dir['args'])}; (Đã được cập nhật!)")
    #     else:
    #         print(f"    Server {idx + 1}: Không có cấu hình SSL.")