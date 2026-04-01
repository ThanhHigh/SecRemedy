# AST from RAM --> Config text file
import json
import os
import argparse
from typing import List, Dict, Any

import crossplane

def build_nginx_config(ast_data: List[Dict[str, Any]], indent_spaces: int = 4) -> str:
    """
    Dung crossplane dich tu ast sang text cau hinh nginx
    Args:
        ast_data (List[Dict[str, Any]]): Danh sach AST duoc trich xuat tu RAM
        indent_spaces (int): So khoang trang de thut vao moi cap do cua cau hinh 
        (giup file de doc hon)
    Returns:
        str: Cau hinh nginx duoc tao ra tu AST
    """
    
    try:
        # Crossplane build nhan vao mot list cac dictionary va tra ve mot string
        # Tham so indent giup format code de doc hon
        nginx_conf_text = ""
        nginx_conf_text = crossplane.build(ast_data, indent=indent_spaces, tabs=False)
        return nginx_conf_text
    except Exception as e:
        print(f"Loi khi build nginx config: {e}")
        return ""

def main():
    # 1. Khoi tao ArgumentParser
    parser_cli = argparse.ArgumentParser(
        description="Builder cua Crossplane: Chuyen AST JSON sang nginx config text"
    )

    parser_cli.add_argument(
        "-i",
        "--input",
        required=True,
        help="Duong dan toi file JSON chua AST"
    )

    parser_cli.add_argument(
        "-o",
        "--output",
        required=True,
        help="Duong dan toi file output de luu cau hinh nginx"
    )

    parser_cli.epilog = "Vi du: python builder.py -i tmp/ast_modified/config_ast_2221_modified.json -o tmp/nginx_fixed_2221/nginx_fixed.conf"

    args = parser_cli.parse_args()

    input_path = os.path.abspath(args.input)
    output_path = os.path.abspath(args.output)

    # 2. Doc file JSON de lay AST
    if not os.path.exists(input_path):
        print(f"File input khong ton tai: {input_path}")
        exit(1)
    
    with open(input_path, 'r', encoding='utf-8') as f_read:
        try:
            modified_ast = json.load(f_read)
        except json.JSONDecodeError as e:
            print(f"Loi dinh dang file JSON khong hop le: {e}")
            exit(1)
    
    # 3. Chay builder
    print(f"Dang dich AST sang cau hinh nginx...")
    nginx_text = build_nginx_config(modified_ast)

    # 4. Ghi cau hinh nginx vao file output
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f_write:
        try:
            f_write.write(nginx_text)
        except Exception as e:
            print(f"Loi khi ghi file output: {e}")
            exit(1)
    
    print(f"Da luu thanh cong cau hinh nginx vao: {output_path}")

if __name__ == "__main__":
    main()
    # Test thu ket qua ra kha oke tuy nhien
    # Chua giong voi config ban dau o khoan include
    # Chua chay test thu server voi file nginx config moi
    