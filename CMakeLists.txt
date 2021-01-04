cmake_minimum_required(VERSION 3.12)
project(diamond-miner VERSION 0.1.10)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(Boost REQUIRED COMPONENTS log log_setup program_options)
find_package(Catch2 REQUIRED)
find_package(Patricia REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(Tins REQUIRED IMPORTED_TARGET libtins)

option(WITH_TESTS "Build tests and enable coverage" OFF)
configure_file(src/diamond-miner-config.h.in diamond-miner-config.h)

# Library TODO: Make everything header and set as INTERFACE instead.
add_library(diamond-miner src/network_utils_t.cpp src/parameters_utils_t.cpp
                          src/sniffer_t.cpp)

target_link_libraries(
  diamond-miner PUBLIC Boost::log Boost::log_setup Patricia::Patricia
                       PkgConfig::Tins Threads::Threads ZLIB::ZLIB)

target_compile_features(diamond-miner PUBLIC cxx_std_17)
target_compile_options(diamond-miner PUBLIC -DBOOST_LOG_DYN_LINK)
target_compile_options(diamond-miner PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner PUBLIC "${PROJECT_BINARY_DIR}")

# Executable
add_executable(diamond-miner-prober src/diamond-miner-prober.cpp)

target_link_libraries(
  diamond-miner-prober PUBLIC Boost::log Boost::log_setup
                              Boost::program_options diamond-miner)

target_compile_features(diamond-miner-prober PUBLIC cxx_std_17)
target_compile_options(diamond-miner-prober PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner-prober PUBLIC "${PROJECT_BINARY_DIR}")

# Tests
if(WITH_TESTS)
  include(Catch)
  include(CodeCoverage)
  include(CTest)

  add_executable(
    diamond-miner-tests
    src/diamond-miner-tests.cpp src/heartbeat_test.cpp
    src/packet_parser_test.cpp src/probe_test.cpp src/rate_limiter_test.cpp
    src/timestamp_test.cpp)
  target_link_libraries(diamond-miner-tests PUBLIC Catch2::Catch2 diamond-miner)
  target_compile_features(diamond-miner-tests PUBLIC cxx_std_17)
  target_compile_options(diamond-miner-tests PRIVATE -Wall -Wextra)
  catch_discover_tests(diamond-miner-tests)

  append_coverage_compiler_flags()
  setup_target_for_coverage_gcovr_xml(
    NAME coverage EXECUTABLE diamond-miner-tests EXCLUDE
    "${PROJECT_SOURCE_DIR}/extern/*")
endif()

# Install
install(TARGETS diamond-miner-prober DESTINATION bin)
