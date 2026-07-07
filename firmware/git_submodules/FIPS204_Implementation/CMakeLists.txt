cmake_minimum_required(VERSION 3.20.0)

set(BOARD_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..//../")
set(BOARD "mc1board")
set(BOARD_FLASH_RUNNER "jlink")
set(BOARD_DEBUG_RUNNER "jlink")

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(FIPS204_Implementation LANGUAGES C CXX)

target_link_libraries(app PRIVATE mbedTLS)

# Allow extended constexpr evaluation for ML-DSA precomputed tables (GCC only)
target_compile_options(app PRIVATE
    -fconstexpr-ops-limit=1000000000
)

# Add source files
target_sources(app PRIVATE
    src/main.cpp
    src/FiPS204_implementation.cpp
    src/USBcommunication.cpp
    src/ECDSA_implementation.cpp
)

# Add include directories
target_include_directories(app PRIVATE
    src/
    src/ml_dsa/
)
