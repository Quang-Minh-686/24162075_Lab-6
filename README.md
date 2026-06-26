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
