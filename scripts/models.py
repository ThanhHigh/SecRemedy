from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import create_engine
import datetime

Base = declarative_base()

class Server(Base):
    __tablename__ = 'servers'
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip_address = Column(String, unique=True, nullable=False)
    ssh_user = Column(String, default="root")
    # Tạm thời bỏ qua password/key để giữ MVP đơn giản
    
    scans = relationship("ScanResult", back_populates="server")

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True, autoincrement=True) 
    server_id = Column(Integer, ForeignKey('servers.id'))
    compliance_score = Column(Integer)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    status = Column(String) # "failed", "passed"
    
    # CỰC KỲ QUAN TRỌNG: Lưu toàn bộ config_ast.json vào đây để TV2 lấy ra dùng
    raw_ast = Column(JSON) 
    
    server = relationship("Server", back_populates="scans")
    failed_rules = relationship("FailedRule", back_populates="scan", cascade="all, delete-orphan")
    remediation = relationship("Remediation", back_populates="scan", uselist=False)

class FailedRule(Base):
    __tablename__ = 'failed_rules'
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_results.id'))
    rule_id = Column(String)
    rule_name = Column(String)
    severity = Column(String)
    
    # Lưu dưới dạng mảng JSON: ["http", "server"]
    target_context = Column(JSON) 
    # Lưu dưới dạng Object JSON: {"directive": "server_tokens", "args": ["off"]}
    recommended_directive = Column(JSON) 
    
    scan = relationship("ScanResult", back_populates="failed_rules")

class Remediation(Base):
    __tablename__ = 'remediations'
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(Integer, ForeignKey('scan_results.id'), unique=True)
    
    # Trạng thái luồng an toàn: "pending_approval", "approved", "applied", "failed"
    status = Column(String, default="pending_approval") 
    
    # Lưu chuỗi Diff Code để hiển thị lên UI cho người dùng duyệt
    diff_text = Column(Text) 
    
    scan = relationship("ScanResult", back_populates="remediation")

# --- Cấu hình kết nối SQLite ---
DATABASE_URL = "sqlite:///./devsecops_nginx.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

def init_db():
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")