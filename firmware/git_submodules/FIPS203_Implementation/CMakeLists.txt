cmake_minimum_required(VERSION 3.20.0)

set(BOARD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..//../")
set(BOARD "mc1board")
set(BOARD_FLASH_RUNNER "jlink")
set(BOARD_DEBUG_RUNNER "jlink")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(FIPS203_Implementation)

# Option to build with mock FIPS203 implementation 
option(USE_FIPS203_MOCK "Build with mock FIPS203 implementation instead of ML-KEM" OFF)
# change this to ON to enable a mock implementation of FIPS203 to test the host programm for false positives

# Propagate compile-time define for selection
if(USE_FIPS203_MOCK)
    target_compile_definitions(app PRIVATE -DUSE_FIPS203_MOCK=1)
else()
    target_compile_definitions(app PRIVATE -DUSE_FIPS203_MOCK=0)
endif()

target_sources(app PRIVATE
    src/main.c
    src/ECDHA_implementation.c
    src/user_usb.c
    src/Fips203_implementation.cpp
    src/Fips203_implementation.c
    src/Fips203_dispatch.c
)

# Enable C++20 for ml-kem library
target_compile_options(app PRIVATE $<$<COMPILE_LANGUAGE:CXX>:-std=c++20>)

target_include_directories(app PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    "${CMAKE_CURRENT_SOURCE_DIR}/Fips203 C++ implementation Full Repo/ml-kem/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/Fips203 C++ implementation Full Repo/sha3/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/Fips203 C++ implementation Full Repo/randomshake/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/Fips203 C++ implementation Full Repo/subtle/include"
)
