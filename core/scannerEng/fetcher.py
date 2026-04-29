import paramiko
import os
import tarfile
import shutil
import argparse # Thư viện chuẩn của Python để xử lý tham số Terminal

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
            print(f"[+] Đã kết nối SSH thành công tới {self.host}:{self.port}")
        except Exception as e:
            print(f"[-] Lỗi kết nối SSH tới {self.host}:{self.port} - {e}")
            raise

    def fetch_config(self, remote_dir='/etc/nginx', local_extract_dir='./tmp/nginx_raw'):
        """Nén cấu hình trên server, tải về và giải nén cục bộ"""
        remote_tar_path = '/tmp/nginx_backup_temp.tar.gz'
        local_tar_path = f'./tmp/nginx_backup_temp_{self.port}.tar.gz' # Thêm port để tránh trùng lặp file nén local

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
            print(f"[*] Đang tải file nén về máy Dev (Lưu tạm tại {local_tar_path})...")
            sftp = self.ssh_client.open_sftp()
            sftp.get(remote_tar_path, local_tar_path)

            # 4. Xóa file nén tạm trên Server
            sftp.remove(remote_tar_path)
            sftp.close()
            print("[+] Đã tải xong và dọn dẹp file tạm trên server.")

            # 5. Giải nén file cục bộ
            print(f"[*] Đang giải nén vào {local_extract_dir}...")
            with tarfile.open(local_tar_path, "r:gz") as tar:
                tar.extractall(path=local_extract_dir)
            
            # 6. Xóa file nén tạm trên máy Dev
            os.remove(local_tar_path)
            print(f"[+] Hoàn tất! Cấu hình Nginx (Port {self.port}) đã sẵn sàng tại: {local_extract_dir}\n")

        except Exception as e:
            print(f"[-] Lỗi trong quá trình fetch data: {e}")
            raise

    def disconnect(self):
        """Đóng kết nối SSH"""
        if self.ssh_client:
            self.ssh_client.close()
            print(f"[+] Đã đóng kết nối SSH ({self.host}:{self.port}).")

# ==========================================
# KHU VỰC CLI (Chạy qua Terminal)
# ==========================================
if __name__ == "__main__":
    # Khởi tạo bộ phân tích tham số
    parser = argparse.ArgumentParser(description="DevSecOps Nginx Config Fetcher")
    
    # Định nghĩa các tham số (Arguments)
    parser.add_argument("-H", "--host", type=str, default="127.0.0.1", help="IP của Server (Mặc định: 127.0.0.1)")
    parser.add_argument("-P", "--port", type=int, help="Port SSH của Server (VD: 2221, 2222)")
    parser.add_argument("-a", "--all-ports", action="store_true", help="Chạy trên tất cả các port (2221, 2222, 2223)")
    parser.add_argument("-u", "--user", type=str, default="root", help="Username SSH (Mặc định: root)")
    parser.add_argument("-p", "--password", type=str, default="root", help="Password SSH (Mặc định: root)")
    parser.add_argument("-o", "--output", type=str, help="Thư mục lưu cấu hình (Mặc định: ./tmp/nginx_raw_<port>)")

    # Lấy các tham số người dùng nhập vào
    args = parser.parse_args()

    if args.all_ports:
        target_ports = []
        try:
            import re
            with open("tests/integration/docker-compose.yml", "r") as f:
                content = f.read()
                matches = re.findall(r'"(\d+):22"', content)
                target_ports = [int(m) for m in matches]
        except Exception as e:
            print(f"[-] Lỗi đọc docker-compose.yml: {e}")
            exit(1)
        if not target_ports:
             print("[-] Không tìm thấy port SSH nào trong docker-compose.yml")
             exit(1)
    elif args.port:
        target_ports = [args.port]
    else:
        parser.error("Bạn phải cung cấp -P/--port hoặc dùng cờ -a/--all-ports.")

    for current_port in target_ports:
        print(f"\n==========================================")
        print(f"[*] BẮT ĐẦU FETCH PORT {current_port}")
        print(f"==========================================")
        # Nếu người dùng không truyền -o (hoặc đang chạy all_ports), tự động tạo tên thư mục theo Port
        output_dir = args.output if (args.output and not args.all_ports) else f"./tmp/nginx_raw_{current_port}"

        # Thực thi logic
        fetcher = NginxFetcher(args.host, current_port, args.user, args.password)
        try:
            fetcher.connect()
            fetcher.fetch_config(local_extract_dir=output_dir)
        except Exception as e:
            print(f"[-] Quá trình thất bại ở port {current_port}: {e}")
        finally:
            fetcher.disconnect()