Tài liệu này chi tiết hóa việc triển khai hệ thống sử dụng **FastAPI** cho Backend và **ReactJS** cho Frontend, kết nối trực tiếp với các module Core (Fetcher, Scanner, Remedy).

## 1. Kiến trúc Backend (FastAPI)

Backend đóng vai trò là trung gian điều phối giữa người dùng và các xử lý nặng ở Core.

### 1.1. Cấu trúc Thư mục API
```text
backend/
├── app/
│   ├── main.py            # Khởi tạo FastAPI và khai báo route
│   ├── core_wrapper.py     # Wrapper kết nối với các module Python Core
│   ├── routes/
│   │   ├── upload.py      # API Upload & SSH Fetcher
│   │   ├── scanner.py     # API Chạy Scanner # Cái này ở Core bên ngoài
│   │   └── remedy.py      # API Xử lý Fix & Diff # Cái này ở Core bên ngoài
│   └── schemas.py         # Pydantic models cho request/response
└── uploads/               # Thư mục lưu trữ tạm thời

```

### 1.2. Danh sách các API Endpoint

#### A. Nhóm Cấu hình (Configuration & Fetching)

* **POST `/api/upload**`:
* *Chức năng*: Nhận file `.zip` hoặc thư mục cấu hình từ Client.
* *Input*: Multipart file.


* **POST `/api/fetch-remote**`:
* *Chức năng*: Gọi `fetcher` trong Core để SSH vào server IP mục tiêu và kéo cấu hình về.
* *Input*: `{ "ip": "...", "port": 22, "username": "...", "password": "..." }`.



#### B. Nhóm Quét (Scanner)

* **GET `/api/scan/{session_id}**`:
* *Chức năng*: Kích hoạt Scanner quét thư mục cấu hình đã upload.
* *Output*: JSON chứa danh sách các lỗi (Violations) và các luật đã vượt qua (Passed rules).



#### C. Nhóm Sửa lỗi (Remedy)

* **POST `/api/remedy/diff**`:
* *Chức năng*: Trả về nội dung so sánh (diff) giữa file gốc và file sau khi được module Remedy đề xuất sửa.
* *Output*: `{ "filename": "...", "original": "...", "fixed": "...", "diff": "..." }`.


* **POST `/api/remedy/approve**`:
* *Chức năng*: Xác nhận phê duyệt từ người dùng để áp dụng thay đổi vào file cấu hình chính thức.


* **GET `/api/remedy/download-safe**`:
* *Chức năng*: Đóng gói toàn bộ cấu hình đã sửa thành file `.zip` để người dùng tải về.



---

## 2. Kiến trúc Frontend (ReactJS)

Frontend sử dụng **TailwindCSS** để UI hiện đại và **Axios** để gọi API.

### 2.1. Các Trang Giao diện Chính

#### 1. Trang Chủ (Upload & Setup)

* **Component**: `UploadPanel.js`
* **Tính năng**:
* Khu vực Drag-and-drop để upload file.
* Form nhập thông tin SSH (IP, Port, User) để fetch từ xa.
* Nút "Bắt đầu phân tích".



#### 2. Trang Kết quả Quét (Dashboard)

* **Component**: `ScanReport.js`
* **Tính năng**:
* Biểu đồ tổng quan (Số lỗi/Số luật pass).
* Bảng danh sách lỗi chi tiết (Mức độ nghiêm trọng: High, Medium, Low).
* Bộ lọc theo loại thiết bị (Cisco, Juniper, etc.).



#### 3. Trang Sửa lỗi (Remedy Workspace)

* **Component**: `DiffViewer.js`
* **Tính năng**:
* Sử dụng thư viện `react-diff-viewer` để hiển thị trực quan sự thay đổi code.
* Form phê duyệt: Checkbox xác nhận từng dòng fix hoặc "Approve All".
* Trạng thái tiến trình (Step-by-step).



#### 4. Trang Quản lý & Tải về

* **Component**: `DownloadCenter.js`
* **Tính năng**:
* Hiển thị lịch sử các phiên quét.
* Nút "Download Hardened Config" cho các cấu hình đã được phê duyệt sửa lỗi hoàn toàn.



---

## 3. Luồng hoạt động của Hệ thống (Workflow)
Cần confirm lại

1. **Bước 1**: Người dùng tải cấu hình lên (Upload) hoặc cung cấp IP để hệ thống tự lấy (Fetcher).
2. **Bước 2**: Hệ thống lưu vào vùng đệm, FastAPI gọi `Scanner.core`. Kết quả trả về danh sách vi phạm.
3. **Bước 3**: Người dùng xem danh sách lỗi trên ReactJS. Nhấn nút "Fix" cho từng mục.
4. **Bước 4**: FastAPI gọi `Remedy.core` để tạo bản nháp sửa lỗi. Frontend hiển thị **Diff**.
5. **Bước 5**: Người dùng kiểm tra Diff, nhấn **Approve**.
6. **Bước 6**: Sau khi hoàn tất, người dùng tải về bộ cấu hình đã an toàn (Safe Config).

---

## 4. Công nghệ đề xuất
Cần confirm
* **Backend**: FastAPI, Pydantic, Paramiko (cho SSH), Python-Levenshtein (tính toán diff).
* **Frontend**: ReactJS, Vite, Tailwind CSS, Lucide React (Icons), Axios.
* **Data Flow**: REST API (JSON).



