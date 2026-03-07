# SecRemedy - Hướng dẫn sử dụng Docker

## Giới thiệu
Dự án SecRemedy sử dụng Docker để thiết lập môi trường test với 2 container Nginx: một container với cấu hình tốt và một container với cấu hình có vấn đề bảo mật.

## Yêu cầu
- Docker
- Docker Compose

## Hướng dẫn chạy

### Build và khởi động containers
```bash
docker compose up -d --build
```

### Dừng containers
```bash
docker compose stop
```

### Khởi động lại containers
```bash
docker compose start
```

### Xóa containers
```bash
docker compose down
```

## Kiểm tra và Test

### 1. Kiểm tra trạng thái containers
Chạy lệnh sau để xem trạng thái container, cả 2 container phải hiện chữ **Up**:
```bash
docker compose ps
```

### 2. Kiểm tra kết nối SSH

#### Kết nối vào máy Bad (cổng 2221)
```bash
ssh root@localhost -p 2221
```
- Khi được hỏi mật khẩu, nhập: `root`

#### Kết nối vào máy Good (cổng 2222)
```bash
ssh root@localhost -p 2222
```
- Mật khẩu: `root`

> **Lưu ý**: Các kết nối SSH này sẽ được sử dụng cho Tool tự động kiểm tra bảo mật sau này.

## Cấu trúc dự án
```
SecRemedy/
├── docker-compose.yml
├── Dockerfile
├── configs/
│   ├── nginx_bad.conf
│   └── nginx_good.conf
└── README.md
```

## Xử lý sự cố

### Containers không khởi động
```bash
# Xem logs
docker compose logs

# Xem logs của container cụ thể
docker compose logs nginx-bad
docker compose logs nginx-good
```

### Port đã được sử dụng
Nếu port 2221 hoặc 2222 đã được sử dụng, bạn có thể chỉnh sửa file `docker-compose.yml` để thay đổi port mapping.
