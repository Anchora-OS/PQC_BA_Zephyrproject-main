cmake_minimum_required(VERSION 3.20.0)

set(BOARD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..//../")
set(BOARD "mc1board")
set(BOARD_FLASH_RUNNER "jlink")
set(BOARD_DEBUG_RUNNER "jlink")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(FIPS205_Implementation)

target_link_libraries(app PRIVATE mbedTLS)

# Add source files here
target_sources(app PRIVATE
    src/main.cpp
    src/Fips205_implementation.c
    src/USBcommunication.cpp
    src/RSAPSS_implementation.cpp
    src/Fips205_Files/sha2_256.c
    src/Fips205_Files/sha2_512.c
    src/Fips205_Files/sha3_api.c
    src/Fips205_Files/sha3_f1600.c
    src/Fips205_Files/slh_dsa.c
    src/Fips205_Files/slh_prehash.c
    src/Fips205_Files/slh_sha2.c
    src/Fips205_Files/slh_shake.c
)

target_include_directories(app PRIVATE
    src/
)

# Suppress C++17 'register' warnings emitted from STM32 HAL third-party headers.
target_compile_options(app PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-register>
)
