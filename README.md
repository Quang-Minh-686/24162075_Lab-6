## 1. Yêu Cầu Hệ Thống & Thư Viện (Dependencies)
* [cite_start]Để biên dịch thành công, hệ thống cần cài đặt các công cụ sau[cite: 34]:
* [cite_start]**Trình biên dịch:** Hỗ trợ tiêu chuẩn **C++17** trở lên (GCC/Clang trên Linux, MSVC trên Windows).
* [cite_start]**Hệ thống Build:** CMake (Phiên bản $\ge$ 3.15)[cite: 25, 344].
* [cite_start]**Thư Viện Mật Mã:** OpenSSL (v3.x) / Crypto++ (tùy thuộc vào phần lõi `pqc_core.h`)[cite: 2].

## 2. build
### Trên Linux:
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
# Chạy chương trình:
./bin/pqtool benchmark

### Trên Windows (Powershell / CMD):
mkdir build
cd build
cmake -B build -G "Unix Makefiles" -DCMAKE_EXE_LINKER_FLAGS="-static -static-libgcc -static-libstdc++"
cmake --build build
 --config Release
# Chạy chương trình:
.\bin\Release\pqtool.exe benchmark

## hiện tiếng việt dùng lệnh : [Console]::OutputEncoding = [System.Text.Encoding]::UTF8


## 3. Hướng Dẫn Sử Dụng Chi Tiết (CLI Usage Examples)
# 3.1. Đo lường hiệu năng (Benchmark)

# Linux
./bin/pqtool benchmark

# Windows
.\bin\pqtool.exe benchmark

## 3.2. Sinh cặp khóa (Key Generation)

./bin/pqtool keygen --algo mldsa-44 --pub pub_mldsa.pem --priv priv_mldsa.pem
./bin/pqtool keygen --algo mlkem-512 --pub pub_mlkem.pem --priv priv_mlkem.pem

## 3.3. Ký và Xác thực chữ ký số (ML-DSA)
# Ký số một tệp tin (hoặc chuỗi văn bản):
./bin/pqtool sign --algo mldsa-44 --in msg.bin --out sig.bin --priv priv_mldsa.pem

# Hoặc ký văn bản text trực tiếp bằng tham số --text
./bin/pqtool sign --algo mldsa-44 --text "Hello PQC" --out sig.bin --priv priv_mldsa.pem

## 3.4. Đóng gói và Giải gói khóa chung (ML-KEM)
# Đóng gói (Encapsulation): Tạo ra bản mã Ciphertext (ct.bin) và Khóa chung bí mật Shared Secret (ss.bin):
./bin/pqtool encaps --pub pub_mlkem.pem --ct ct.bin --ss ss.bin
# Giải gói (Decapsulation): Sử dụng khóa bí mật để khôi phục lại Khóa chung bí mật:
./bin/pqtool decaps --priv priv_mlkem.pem --ct ct.bin --ss ss.bin --verbose

## 3.5. Quản lý chứng chỉ Mini-Project
# Tạo chứng chỉ cấu trúc JSON được ký bởi CA:
./bin/pqtool cert-create --subject "User_Alice" --pub pub_mldsa.pem --priv ca_priv.pem --issuer "PQ-RootCA" --out cert.json

# Xác thực tính toàn vẹn và chữ ký của chứng chỉ:
./bin/pqtool cert-verify --in cert.json --pub ca_pub.pem\

## 3.6. Chạy các bài kiểm tra mẫu từ NIST (Known Answer Tests - KAT)
./bin/pqtool --kat vectors.json

## 4. Các Giới Hạn Đã Biết (Known Limitations)
An toàn kênh kề (Side-Channel Compliance): Hệ thống chưa được tối ưu hóa ở mức mã máy để chống lại hoàn toàn các cuộc tấn công dựa trên phân tích thời gian (Timing Attacks) hoặc phân tích điện năng tiêu thụ.

Quản lý bộ nhớ an toàn: Việc dọn dẹp các vùng nhớ chứa khóa bí mật chưa áp dụng cơ chế xóa sạch an toàn (Secure Allocator / Zeroization) khi chương trình kết thúc hoặc bị crash đột ngột.
