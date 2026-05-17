import os

class Canvas:
    def __init__(self, width, height=65):
        self.width = width
        self.height = height
        self.grid = [[' '] * width for _ in range(height)]
        self.max_y = 0

    def draw_text(self, x, y, text):
        for i, char in enumerate(text):
            if x + i < self.width:
                self.grid[y][x + i] = char
        self.max_y = max(self.max_y, y)

    def draw_box(self, x, y, w, h, title="", lines=[]):
        # Draw border
        self.draw_text(x, y, "+" + "-" * (w - 2) + "+")
        for i in range(1, h - 1):
            self.draw_text(x, y + i, "|")
            self.draw_text(x + w - 1, y + i, "|")
        self.draw_text(x, y + h - 1, "+" + "-" * (w - 2) + "+")
        
        # Draw title if any
        if title:
            title_x = x + (w - len(title)) // 2
            self.draw_text(title_x, y + 1, title)
            
        # Draw lines
        for i, line in enumerate(lines):
            self.draw_text(x + 2, y + (2 if title else 1) + i, line)

    def get_string(self):
        lines = []
        for y in range(self.max_y + 1):
            lines.append("".join(self.grid[y]).rstrip())
        return "\n".join(lines) + "\n"

def build_diagram():
    canvas = Canvas(125, 65)
    
    # Separator
    sep = "=" * 125
    canvas.draw_text(0, 0, sep)
    
    # TẦNG 1: FRONTEND - STREAMLIT UI
    canvas.draw_text(0, 1, "[ TẦNG 1: FRONTEND - STREAMLIT UI ]")
    
    # Dashboard UI: X = 2 to X = 39 (Width 38)
    canvas.draw_box(2, 3, 38, 5, lines=[
        "Dashboard UI",
        "- Hiển thị Điểm số (Score)",
        "- Danh sách luật CIS vi phạm"
    ])
    
    # Remediation UI: X = 46 to X = 97 (Width 52)
    canvas.draw_box(46, 3, 52, 5, lines=[
        "Remediation UI",
        "- Nút \"Dry-Run\" -> Hiển thị Diff Code",
        "- Badge \"Syntax OK\" -> Mở khóa nút \"Approve\""
    ])
    
    # Flow indicators under Tầng 1 UI
    canvas.draw_text(12, 8, "^")
    canvas.draw_text(30, 8, "|")
    canvas.draw_text(55, 8, "^")
    canvas.draw_text(73, 8, "|")
    canvas.draw_text(88, 8, "|")
    
    canvas.draw_text(12, 9, "| (JSON Data)")
    canvas.draw_text(30, 9, "| (Click Scan)")
    canvas.draw_text(55, 9, "| (Diff & Status)")
    canvas.draw_text(73, 9, "| (Dry-Run)")
    canvas.draw_text(88, 9, "| (Approve)")
    
    canvas.draw_text(0, 10, sep)
    
    # TẦNG 2: BACKEND API - FASTAPI
    canvas.draw_text(0, 11, "[ TẦNG 2: BACKEND API - FASTAPI ]")
    
    # FastAPI Endpoints box: X = 49 to X = 75 (Width 27)
    canvas.draw_box(49, 13, 27, 6, lines=[
        "FastAPI Endpoints",
        " /scan",
        " /dry-run",
        " /approve"
    ])
    
    # Outputs from FastAPI box
    canvas.draw_text(51, 19, "|")
    canvas.draw_text(62, 19, "|")
    canvas.draw_text(73, 19, "|")
    
    # Horizontal connection lines
    canvas.draw_text(20, 20, "." + "-" * 30 + "'")
    canvas.draw_text(62, 20, "|")
    canvas.draw_text(73, 20, "'" + "-" * 30 + ".")
    
    # Labels
    canvas.draw_text(20, 21, "| (Gọi luồng Scan)")
    canvas.draw_text(62, 21, "| (Gọi luồng Dry-Run)")
    canvas.draw_text(104, 21, "| (Gọi luồng Execute)")
    
    # Arrows pointing to Tầng 3
    canvas.draw_text(20, 22, "v")
    canvas.draw_text(62, 22, "v")
    canvas.draw_text(104, 22, "v")
    
    canvas.draw_text(0, 23, sep)
    
    # TẦNG 3: CORE ENGINES
    canvas.draw_text(0, 24, "[ TẦNG 3: CORE ENGINES (XỬ LÝ LOGIC & DEVSECOPS PIPELINE) ]")
    
    # Col 1 (Scanner Engine): X = 1..38
    canvas.draw_box(1, 26, 38, 15, title="SCANNER ENGINE", lines=[
        "",
        "SSH Fetcher",
        " | (Kéo /etc/nginx/ về local)",
        " v",
        "Crossplane Wrapper",
        " | (Parse Text -> ast_dict)",
        " v",
        "Rules Evaluation",
        " | (Duyệt AST qua BaseRule)",
        " v",
        "Scanner & DB",
        " | (Tính điểm, lưu SQLite)"
    ])
    
    # Col 2 (Remediation Engine): X = 43..80
    canvas.draw_box(43, 26, 38, 20, title="REMEDIATION ENGINE", lines=[
        "",
        "AST Locator",
        " | (Tìm vị trí cần sửa trong AST",
        " |  theo scan_result.json)",
        " v",
        "AST Injector",
        " | (Tiêm code -> mod_ast)",
        " v",
        "Crossplane Builder",
        " | (Build AST -> fixed.conf)",
        " v",
        "Diff Generator",
        " | (So sánh -> Unified Diff)",
        " v",
        "Safe Validator",
        " | (Upload /tmp/fixed.conf &",
        " |  chạy nginx -t -c)"
    ])
    
    # Col 3 (Safe Pipeline): X = 85..122
    canvas.draw_box(85, 26, 38, 12, title="SAFE PIPELINE", lines=[
        "",
        "SSH Backup",
        " | (Chạy cp -R /etc/nginx)",
        " v",
        "Executor",
        " | (Ghi cấu hình đã sửa vào file",
        " |  mới (output cuối cùng).",
        " |  không động vào file thật",
        " |  trên target servers)"
    ])
    
    # Flow lines below bottom borders:
    # Column 3 ends at Y = 37. Vertical flow line at X = 104.
    for y in range(38, 48):
        canvas.draw_text(104, y, "|")
        
    # Column 1 ends at Y = 40. Vertical flow line at X = 20.
    for y in range(41, 48):
        canvas.draw_text(20, y, "|")
        
    # Column 2 ends at Y = 45. Vertical flow line at X = 62.
    for y in range(46, 48):
        canvas.draw_text(62, y, "|")
        
    # TẦNG 4 Separator
    t4_sep = "=" * 19 + "|" + "=" * 41 + "|" + "=" * 41 + "|" + "=" * 21
    canvas.draw_text(0, 48, t4_sep)
    
    # TẦNG 4: INFRASTRUCTURE
    canvas.draw_text(0, 49, "[ TẦNG 4: INFRASTRUCTURE ]")
    
    # SQLite DB: X = 2 to X = 39 (Width 38)
    # The top border of SQLite DB has a 'v' at X = 20 (corresponding to Col 1 flow)
    # Box starts at X = 2, width = 38. So border is X = 2 to X = 39.
    # We will draw a 'v' at X = 20.
    # Let's draw the box:
    canvas.draw_box(2, 51, 38, 7, lines=[
        " [ SQLite DB ]",
        "",
        "- Bảng Servers",
        "- Bảng ScanResults",
        "- Bảng Remediations"
    ])
    canvas.draw_text(20, 51, "v")
    
    return canvas.get_string()

if __name__ == "__main__":
    diagram_content = build_diagram()
    target_path = "/home/nguye24/projects/sandbox/SecRemedy/docs/architecture/general_data_flow.txt"
    os.makedirs(os.path.dirname(target_path), exist_ok=True)
    with open(target_path, "w", encoding="utf-8") as f:
        f.write(diagram_content)
    print("Successfully reformatted diagram.")
