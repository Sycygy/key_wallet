cmake_minimum_required(VERSION 3.10)
project(key_wallet VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Release when not specified
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build." FORCE)
endif()

# Put binaries under build/bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# ── OpenSSL ─────────────────────────────────────────────────────────────────
find_package(OpenSSL 3.2 REQUIRED)

# ── Main executable ──────────────────────────────────────────────────────────
add_executable(key_wallet
    src/main.cpp
    src/cli/input.cpp
)

target_include_directories(key_wallet PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${OPENSSL_INCLUDE_DIR}
)

target_compile_options(key_wallet PRIVATE -Wall -Wextra -Wpedantic -O2)

target_link_libraries(key_wallet PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# ── Install ──────────────────────────────────────────────────────────────────
install(TARGETS key_wallet RUNTIME DESTINATION bin)

# ── Tests ────────────────────────────────────────────────────────────────────
enable_testing()
add_subdirectory(tests)

# ── Convenience package target ───────────────────────────────────────────────
add_custom_target(package_install
    COMMAND ${CMAKE_COMMAND} --build ${CMAKE_BINARY_DIR} --target install
    COMMENT "Build and install to CMake install prefix")
