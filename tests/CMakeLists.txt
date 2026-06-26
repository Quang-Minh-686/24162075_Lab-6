cmake_minimum_required(VERSION 3.15)

set(TEST_SOURCES
    test_main.cpp
    ../src/pqc_core.cpp
    ../src/certificate.cpp
)

add_executable(pqtests ${TEST_SOURCES})

target_include_directories(pqtests PRIVATE ../include)

if(MSVC)
    target_compile_options(pqtests PRIVATE /W4 /EHsc)
    target_compile_definitions(pqtests PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
    target_compile_options(pqtests PRIVATE -Wall -Wextra)
endif()

add_test(NAME PqcRegressionTests COMMAND pqtests)