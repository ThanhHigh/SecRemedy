import os
import datetime
import logging

import paramiko

from core.remedyEng.archive.paths import ROOT_DIR

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
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            logging.info(f"Dang ket noi SSH toi {self.host}:{self.port} voi ten nguoi dung la {self.username}...")

            self.ssh_client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10
            )

            logging.info("SSH ket noi thanh cong.")
        except Exception as e:
            logging.error(f"Loi khong the ket noi SSH: {e}")
            raise

        
    
    def disconnect(self):
        """
        Dong ket noi SSH
        """
        if self.ssh_client:
            self.ssh_client.close()
            logging.info("SSH ket noi da duoc dong.")
    
    def create_backup(self, source_dir):
        """
        Thuc hien backup cau hinh Nginx
        Luu tru file backup voi ten co dinh kem thoi gian
        File backup se duoc luu trong thu muc backup_dir tren server
        Tuc la o trong container server
        Mac dinh la /etc/nginx
        Neu mount volume thi se o trong thu muc /config
        Tra ve duong dan backup neu thanh cong
        """
        if not self.ssh_client:
            logging.error("Chua ket noi SSH. Vui long goi connect() truoc.")
            return None
        
        # Tao timestamp de dat ten file backup
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_dir = f"{source_dir}_backup_{timestamp}"

        # Thuc hien lenh sao chep thu muc cau hinh Nginx sang thu muc backup
        command = f"cp -a {source_dir} {backup_dir}"

        logging.info(f"Dang thuc hien lenh backup: {command}...")

        try:
            stdin, stdout, stderr = self.ssh_client.exec_command(command)

            # Doc ket qua lenh Linux de biet thanh cong (=0) hay that bai (khac 0)
            exit_status = stdout.channel.recv_exit_status()
            if exit_status == 0:
                logging.info(f"Backup thanh cong. File backup duoc luu tai: {backup_dir}")
                return backup_dir
            else:
                error_message = stderr.read().decode().strip()
                logging.error(f"Backup that bai. Loi: {error_message}")
                return None
        except Exception as e:
            logging.error(f"Loi khi thuc hien lenh backup: {e}")
            return None




# Test
if __name__ == "__main__":
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
        backup_dir = backup_manager.create_backup(source_dir)

        if backup_dir:
            logging.info(f"Backup duoc luu tai: {backup_dir}")
        else:
            logging.error("Backup that bai.")


    except Exception as e:
        logging.error(f"Error during backup: {e}")
    finally:        
        backup_manager.disconnect()
    
