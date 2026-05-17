"""
Step 6 — Remote Executor

Backup /etc/nginx/ trên server rồi SFTP push hardened config lên.
Chỉ chạy SAU KHI Approve Gate mở (được gọi từ RemedyEngine.execute()).
Không chạy `nginx -s reload` — nằm ngoài scope Executor.

Dùng paramiko.SSHClient (SSH exec) + SFTPClient (file push).
"""

from pathlib import Path

import paramiko


class RemoteExecutor:
    def __init__(
        self,
        host: str,
        port: int,
        username: str,
        password: str | None = None,
        key_path: str | None = None,
    ) -> None:
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path

    # ------------------------------------------------------------------
    def backup(self) -> bool:
        """SSH: cp -R /etc/nginx/ /etc/nginx.bak/ trên target server."""
        try:
            with self._connect() as client:
                _, stdout, _ = client.exec_command(
                    "cp -R /etc/nginx/ /etc/nginx.bak/"
                )
                return stdout.channel.recv_exit_status() == 0
        except Exception:
            return False

    def push(self, local_files: dict[str, str]) -> bool:
        """
        SFTP upload nhiều file lên server.

        local_files: {local_path: remote_path}
          VD: {"tmp/hardened_configs/2222/nginx.conf": "/etc/nginx/nginx.conf"}
        """
        try:
            with self._connect() as client:
                with client.open_sftp() as sftp:
                    for local_path, remote_path in local_files.items():
                        sftp.put(local_path, remote_path)
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    def _connect(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs: dict = {
            "hostname": self.host,
            "port": self.port,
            "username": self.username,
        }
        if self.password:
            kwargs["password"] = self.password
        if self.key_path:
            kwargs["key_filename"] = self.key_path
        client.connect(**kwargs)
        return client
