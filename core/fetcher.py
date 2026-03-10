import paramiko
import os
import tarfile
import shutil

class NginxFetcher:
    def __init__(self, host, port, username, password):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.ssh_client = None

    def connect(self):
        """Khởi tạo kết nối SSH tới Server mục tiêu"""
        try:
            self.ssh_client = paramiko.SSHClient()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh_client.connect(
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                timeout=10
            )
            print(f"[+] Đã kết nối SSH thành công tới {self.host}")
        except Exception as e:
            print(f"[-] Lỗi kết nối SSH: {e}")
            raise

    def fetch_config(self, remote_dir='/etc/nginx', local_extract_dir='./tmp/nginx_raw'):
        """Nén cấu hình trên server, tải về và giải nén cục bộ"""
        remote_tar_path = '/tmp/nginx_backup_temp.tar.gz'
        local_tar_path = './tmp/nginx_backup_temp.tar.gz'

        # 1. Tạo thư mục local nếu chưa có, nếu có rồi thì xóa đi tạo lại cho sạch
        if os.path.exists(local_extract_dir):
            shutil.rmtree(local_extract_dir)
        os.makedirs(local_extract_dir, exist_ok=True)
        os.makedirs('./tmp', exist_ok=True)

        try:
            # 2. Chạy lệnh nén trên Server
            # Dùng -C để cd vào thư mục trước khi nén, giúp tránh bị dính đường dẫn tuyệt đối
            tar_command = f"tar -czf {remote_tar_path} -C {remote_dir} ."
            print(f"[*] Đang nén cấu hình trên server: {tar_command}")
            stdin, stdout, stderr = self.ssh_client.exec_command(tar_command)
            
            # Kiểm tra lỗi nếu có
            error = stderr.read().decode().strip()
            if error:
                print(f"[-] Cảnh báo từ server: {error}")

            # 3. Mở SFTP để tải file về
            print("[*] Đang tải file nén về máy Dev...")
            sftp = self.ssh_client.open_sftp()
            sftp.get(remote_tar_path, local_tar_path)

            # 4. Xóa file nén tạm trên Server (Clean up)
            sftp.remove(remote_tar_path)
            sftp.close()
            print("[+] Đã tải xong và dọn dẹp file tạm trên server.")

            # 5. Giải nén file cục bộ
            print(f"[*] Đang giải nén vào {local_extract_dir}...")
            with tarfile.open(local_tar_path, "r:gz") as tar:
                tar.extractall(path=local_extract_dir)
            
            # 6. Xóa file nén tạm trên máy Dev
            os.remove(local_tar_path)
            print(f"[+] Hoàn tất! Cấu hình Nginx đã sẵn sàng tại: {local_extract_dir}")

        except Exception as e:
            print(f"[-] Lỗi trong quá trình fetch data: {e}")
            raise

    def disconnect(self):
        """Đóng kết nối SSH"""
        if self.ssh_client:
            self.ssh_client.close()
            print("[+] Đã đóng kết nối SSH.")

# ==========================================
# KHU VỰC TEST (Chỉ chạy khi chạy trực tiếp file này)
# ==========================================
if __name__ == "__main__":
    # TODO: Thay đổi thông tin này khớp với Docker Lab (T2) của bạn
    LAB_HOST = "127.0.0.1" 
    LAB_PORT = 2221         # Port SSH map từ Docker ra ngoài
    LAB_USER = "root"
    LAB_PASS = "root"       # Mật khẩu bạn đã set trong Docker

    fetcher = NginxFetcher(LAB_HOST, LAB_PORT, LAB_USER, LAB_PASS)
    try:
        fetcher.connect()
        # Mặc định sẽ lấy /etc/nginx và lưu vào ./tmp/nginx_raw
        fetcher.fetch_config() 
    finally:
        fetcher.disconnect()