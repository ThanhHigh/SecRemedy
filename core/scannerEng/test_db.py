import json
import os
from sqlalchemy.orm import sessionmaker
from models import engine, init_db, Server, ScanResult, FailedRule

# --- Bước 0: Xóa DB cũ để tạo lại schema mới (Chỉ dùng khi Dev) ---
if os.path.exists("./devsecops_nginx.db"):
    os.remove("./devsecops_nginx.db")
    print("Đã xóa database cũ.")

# 1. Khởi tạo DB
init_db()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

# 2. Đọc file Mock JSON
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONTRACTS_DIR = os.path.join(BASE_DIR, '../contracts')

with open(os.path.join(CONTRACTS_DIR, 'scan_result.json'), 'r') as f:
    scan_data = json.load(f)

# Giả lập đọc luôn file AST
with open(os.path.join(CONTRACTS_DIR, 'config_ast.json'), 'r') as f:
    ast_data = json.load(f)

# 3. Insert dữ liệu vào Database
try:
    # Tạo Server trước (nếu chưa có)
    server = db.query(Server).filter(Server.ip_address == scan_data["server_ip"]).first()
    if not server:
        server = Server(ip_address=scan_data["server_ip"])
        db.add(server)
        db.commit()
        db.refresh(server)

    # Tạo ScanResult
    new_scan = ScanResult(
        id=int(scan_data["scan_id"]),
        server_id=server.id,
        compliance_score=scan_data["compliance_score"],
        status=scan_data["status"],
        raw_ast=ast_data  # Lưu AST vào DB
    )
    db.add(new_scan)
    db.commit()

    # Tạo các FailedRules
    for rule in scan_data["failed_rules"]:
        new_rule = FailedRule(
            scan_id=new_scan.id,
            rule_id=rule["rule_id"],
            rule_name=rule["rule_name"],
            severity=rule["severity"],
            target_context=rule["target_context"],
            recommended_directive=rule["recommended_directive"]
        )
        db.add(new_rule)

    db.commit()
    print("Đã lưu thành công Mock Data vào SQLite!")

except Exception as e:
    print(f"Lỗi: {e}")
    db.rollback()
finally:
    db.close()