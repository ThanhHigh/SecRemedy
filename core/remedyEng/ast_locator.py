import json
import os
from typing import List, Dict, Any

def locate_blocks(parsed_ast: List[Dict[str, Any]], context_path: List[str]) -> List[List[Dict[str, Any]]]:
    """
    Hàm đệ quy tìm kiếm các block trong cây AST của Nginx dựa trên context_path.
    
    Args:
        parsed_ast (List[Dict]): Mảng 'parsed' chứa cấu trúc Nginx (hoặc một block con).
        context_path (List[str]): Đường dẫn context cần tìm. VD: ["http", "server"]
        
    Returns:
        List[List[Dict]]: Danh sách các tham chiếu (references) trỏ tới các block tìm được.
                          Trả về danh sách vì có thể có nhiều block cùng tên (VD: nhiều block 'server').
    """
    # Điều kiện dừng: Nếu context_path rỗng, nghĩa là ta đã đến đích.
    # Trả về chính block hiện tại (được bọc trong list để đồng nhất kiểu trả về).
    if not context_path:
        return [parsed_ast]

    current_target = context_path[0]
    remaining_path = context_path[1:]
    
    found_blocks = []

    # Duyệt qua từng directive trong cấp độ hiện tại
    for item in parsed_ast:
        # Nếu directive khớp với target hiện tại và nó có chứa một 'block' (danh sách các directive con)
        if item.get("directive") == current_target and "block" in item:
            # Gọi đệ quy để đi sâu vào block con với phần path còn lại
            deep_blocks = locate_blocks(item["block"], remaining_path)
            found_blocks.extend(deep_blocks)

    return found_blocks

def extract_main_parsed_ast(crossplane_output: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Hàm tiện ích để lấy ra mảng 'parsed' của file cấu hình chính từ output của Crossplane.
    """
    # Trong thực tế, có thể có nhiều file do lệnh 'include'. 
    # MVP: Ta ưu tiên lấy file đầu tiên (thường là nginx.conf hoặc file đang xét).
    if "config" in crossplane_output and len(crossplane_output["config"]) > 0:
        return crossplane_output["config"][0].get("parsed", [])
    return []

# ==========================================
# KHỐI TEST (Chỉ chạy khi chạy trực tiếp file này)
# ==========================================
if __name__ == "__main__":
    # 1. Đọc file JSON mẫu từ thư mục contracts
    config_path = os.path.join(os.path.dirname(__file__), "..", "..", "contracts", "config_ast.json")
    
    try:
        with open(config_path, "r") as f:
            raw_data = json.load(f)
    except FileNotFoundError:
        print(f"[-] Không tìm thấy file config_ast.json tại: {config_path}")
        exit(1)

    # 2. Trích xuất mảng parsed
    main_ast = extract_main_parsed_ast(raw_data)
    
    print("--- TEST CASE 1: Tìm block 'http' ---")
    http_blocks = locate_blocks(main_ast, ["http"])
    print(f"[+] Tìm thấy {len(http_blocks)} block 'http'.")
    # In thử directive đầu tiên trong block http tìm được
    if http_blocks:
        print(f"    Directive đầu tiên trong http: {http_blocks[0][0]['directive']} (line {http_blocks[0][0]['line']})")

    print("\n--- TEST CASE 2: Tìm block 'server' bên trong 'http' ---")
    server_blocks = locate_blocks(main_ast, ["http", "server"])
    print(f"[+] Tìm thấy {len(server_blocks)} block 'server'.")
    for idx, block in enumerate(server_blocks):
        # Tìm directive 'listen' để chứng minh ta đã lấy đúng block
        listen_dir = next((d for d in block if d.get("directive") == "listen"), None)
        listen_args = listen_dir["args"] if listen_dir else "Unknown"
        print(f"    Server {idx + 1}: listen {listen_args}")

    print("\n--- TEST CASE 3: Tìm context không tồn tại (VD: 'mail') ---")
    mail_blocks = locate_blocks(main_ast, ["mail"])
    print(f"[+] Tìm thấy {len(mail_blocks)} block 'mail'.")