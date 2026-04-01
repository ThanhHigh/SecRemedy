import difflib
import argparse

from typing import Optional

def generate_diff(origin: str, modified: str) -> Optional[str]:
    """
    So sanh noi dung cau hinh Nginx goc va Sau khi sua doi
    Tra ve chuoi dinh dang Unified Diff (~~ git diff)

    Args:
        origin (str): Noi dung cau hinh Nginx goc
        modified (str): Noi dung cau hinh Nginx sau khi sua doi
        file_name (str): Ten file dang duoc so sanh
    Returns:
        str: Chuoi diff chua '+' va '-' de hien thi su khac biet giua 2 noi dung
             Tra ve None neu khong co su khac biet giua 2 noi dung
    """
    # difflib yeu cau dau vao la mot list cac string
    # Do do ta phai dung splitlines() de chuyen noi dung tu string sang list cac string
    # Buoc 1 : Chuyen noi dung tu string sang list cac string
    origin_lines = origin.splitlines()
    modified_lines = modified.splitlines()

    # Buoc 2 : Kiem tra nhanh neu khong co su khac biet thi khong can sinh Diff
    if origin_lines == modified_lines:
        return None
    
    # Buoc 3 : Su dung difflib.unified_diff de sinh Diff
    """
    For inputs that do not have trailing newlines, set the lineterm
    argument to "" so that the output will be uniformly newline free.
    (from difflib documentation)
    """
    diff_generator = difflib.unified_diff(
        a = origin_lines,
        b = modified_lines,
        fromfile = "a (original)",
        tofile = "b (modified)",
        lineterm = "" # Nhu mac dinh
    )

    # Buoc 4 : Noi cac dong diff lai thanh mot string va xuong dong
    diff_text = "\n".join(diff_generator)

    # Trong truong hop lineterm = "\n" thi diff_text nhu duoi. Nguoc lai nhu tren
    # diff_text = "".join(diff_generator)
    return diff_text

if __name__ == "__main__":
    # Khai bao ArgumentParser
    parser_cli = argparse.ArgumentParser(description="Diff Generator for Nginx Configurations")
    parser_cli.add_argument(
        "--origin",
        required=True,
        help="Path to the original Nginx configuration file"
    )
    parser_cli.add_argument(
        "--modified",
        required=True,
        help="Path to the modified Nginx configuration file"
    )
    args = parser_cli.parse_args()
    

    # Lay input 1: conf bi thieu cau hinh bao mat
    config_origin = ""
    origin_path = args.origin
    try:
        with open(origin_path, "r") as f_read:
            config_origin = f_read.read()
    except FileNotFoundError:
        print(f"File not found: {origin_path}")

    # Lay input 2: conf sau khi da duoc sua doi
    config_modified = ""
    modified_path = args.modified
    try:
        with open(modified_path, "r") as f_read:
            config_modified = f_read.read()
    except FileNotFoundError:
        print(f"File not found: {modified_path}")
    

    print("Đang chạy Dry-Run Diff Generator...\n")
    print("-" * 40)

    result_diff = generate_diff(config_origin, config_modified)
    if result_diff:
        print(result_diff)
    else:
        print("Cấu hình đã an toàn, không có thay đổi nào được đề xuất.")