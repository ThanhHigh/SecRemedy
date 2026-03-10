import json
import os
from typing import List, Dict, Any
from ast_locator import locate_blocks, extract_main_parsed_ast

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
    # 1. Đọc file AST gốc (từ Task 12)
    # Tìm đường dẫn tuyệt đối đến thư mục gốc của project (SecRemedy)
    current_dir = os.path.dirname(os.path.abspath(__file__))  # core/remedyEng/
    project_root = os.path.dirname(os.path.dirname(current_dir))  # SecRemedy/
    config_ast_path = os.path.join(project_root, "contracts", "config_ast.json")
    
    try:
        with open(config_ast_path, "r") as f:
            raw_data = json.load(f)
            main_ast = extract_main_parsed_ast(raw_data)
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

    print("[*] Đang tiến hành Inject cấu hình an toàn vào AST...")
    modified_ast = inject_remediations(main_ast, mock_failed_rules)
    
    # 3. In ra kết quả để kiểm chứng
    print("\n[+] KẾT QUẢ SAU KHI INJECT:")
    
    # Kiểm tra block HTTP (Xem có server_tokens và add_header chưa)
    http_block = locate_blocks(modified_ast, ["http"])[0]
    print("\n--- Các directive mới trong block 'http' ---")
    for d in http_block:
        if d.get("directive") in ["server_tokens", "add_header"]:
            print(f"    {d['directive']} {' '.join(d['args'])};")
            
    # Kiểm tra block Server (Xem ssl_protocols đã bị ghi đè chưa)
    server_blocks = locate_blocks(modified_ast, ["http", "server"])
    print("\n--- Kiểm tra ghi đè 'ssl_protocols' trong các block 'server' ---")
    for idx, s_block in enumerate(server_blocks):
        ssl_dir = next((d for d in s_block if d.get("directive") == "ssl_protocols"), None)
        if ssl_dir:
            print(f"    Server {idx + 1}: ssl_protocols {' '.join(ssl_dir['args'])}; (Đã được cập nhật!)")
        else:
            print(f"    Server {idx + 1}: Không có cấu hình SSL.")