import os
import datetime
import logging

import paramiko

from paths import ROOT_DIR

# Cau hinh logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

# Su dung class Nginx Backup Manager de su dung ve sau
class NginxBackupManager:
    def __init__(self, host, port, username, password):
        """
        Khoi tao thong tin ket noi SSH
        Ho tro Password va SSH Key
        """
        self.host = host
        self.port = port
        self.username = username
        self.password = password

    def connect(self):
        """
        Thiet lap ket noi SSH den server
        """

    
    def disconnect(self):
        """
        Dong ket noi SSH
        """
    
    def create_backup(self, backup_dir, source_dir):
        """
        Thuc hien backup cau hinh Nginx
        Luu tru file backup voi ten co dinh kem thoi gian
        """

# Test
if __name__ == "__main__":
    # Khoi tao thu muc luu tru backup
    # Mac dinh la root/backups
    backup_dir = os.path.join(ROOT_DIR, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    # Thu muc source chua cau hinh Nginx tren server
    # Mac dinh la /etc/nginx
    source_dir = "/etc/nginx"
    # Thong tin server de ket noi
    TARGET_IP = "127.0.0.1"
    TARGET_PORT = 2221
    SSH_USERNAME = "root"
    SSH_PASSWORD = "root"

    # Khoi tao Manager
    backup_manager = NginxBackupManager(
        host = TARGET_IP,
        port = TARGET_PORT,
        username = SSH_USERNAME,
        password = SSH_PASSWORD
    )

    try:
        backup_manager.connect()
        backup_manager.create_backup(backup_dir, source_dir)


    except Exception as e:
        logging.error(f"Error during backup: {e}")
    finally:        
        backup_manager.disconnect()
    
