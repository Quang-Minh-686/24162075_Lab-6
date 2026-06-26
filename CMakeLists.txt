cmake_minimum_required(VERSION 3.15)
project(PostQuantumCryptoLab6 
        VERSION 1.0.0 
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_BINARY_DIR})
    message(FATAL_ERROR "Lỗi: Không cho phép In-Source Build! Vui lòng tạo thư mục build riêng:
    mkdir build && cd build
    cmake ..
    cmake --build .")
endif()

include_directories(include)

set(SOURCES
    src/pqc_core.cpp
    src/certificate.cpp
    src/main.cpp
)

add_executable(pqtool ${SOURCES})

if(MSVC)
    target_compile_options(pqtool PRIVATE /W4 /O2 /EHsc)
    target_compile_definitions(pqtool PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(pqtool PRIVATE -Wall -Wextra -O3 -march=native)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

enable_testing()
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests/CMakeLists.txt")
    add_subdirectory(tests)
endif()

message(STATUS "--------------------------------------------------------")
message(STATUS "Cấu hình thành công Lab 6: Post-Quantum Crypto Tool")
message(STATUS "Hệ điều hành:     ${CMAKE_SYSTEM_NAME}")
message(STATUS "Trình biên dịch:   ${CMAKE_CXX_COMPILER_ID} (Phiên bản: ${CMAKE_CXX_COMPILER_VERSION})")
message(STATUS "File thực thi sẽ được xuất tại: ${CMAKE_BINARY_DIR}/bin/")
message(STATUS "--------------------------------------------------------")