cmake_minimum_required(VERSION 3.12)
project(diamond-miner VERSION 0.2.4)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Catch2 REQUIRED)
find_package(NetUtils REQUIRED)
find_package(Patricia REQUIRED)
find_package(spdlog REQUIRED)
find_package(Tins REQUIRED)
find_package(Threads REQUIRED)

option(WITH_COVERAGE "Enable code coverage" OFF)
option(WITH_SANITIZER "Enable compiler sanitizers" OFF)
configure_file(src/diamond-miner-config.h.in diamond-miner-config.h)

include(Catch)
include(CTest)

# Library
add_library(diamond-miner INTERFACE)
target_compile_features(diamond-miner INTERFACE cxx_std_20)
target_include_directories(diamond-miner
                           INTERFACE "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
  diamond-miner INTERFACE NetUtils::NetUtils Patricia::Patricia tins
                          spdlog::spdlog Threads::Threads)

# Executable (Prober)
add_executable(diamond-miner-prober src/diamond-miner-prober.cpp)
target_compile_options(diamond-miner-prober PRIVATE -Wall -Wextra -pedantic)
target_include_directories(diamond-miner-prober PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(diamond-miner-prober PRIVATE Boost::program_options
                                                   diamond-miner)

# Executable (Reader)
add_executable(diamond-miner-reader src/diamond-miner-reader.cpp)
target_compile_options(diamond-miner-reader PRIVATE -Wall -Wextra -pedantic)
target_include_directories(diamond-miner-reader PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(diamond-miner-reader PRIVATE Boost::program_options
                                                   diamond-miner)

# Executable (Benchmarks)
file(GLOB BENCH_SOURCES tests/*_bench.cpp)
add_executable(diamond-miner-bench ${BENCH_SOURCES})
target_compile_options(diamond-miner-bench PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(diamond-miner-bench PRIVATE Catch2::Catch2WithMain
                                                  diamond-miner)
catch_discover_tests(diamond-miner-bench)

# Executable (Tests)
file(GLOB TESTS_SOURCES tests/*_test.cpp)
add_executable(diamond-miner-tests ${TESTS_SOURCES})
target_compile_options(diamond-miner-tests PRIVATE -Wall -Wextra -pedantic)
target_link_libraries(diamond-miner-tests PRIVATE Catch2::Catch2WithMain
                                                  diamond-miner)
catch_discover_tests(diamond-miner-tests)

if(WITH_COVERAGE)
  include(CodeCoverage)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")
  setup_target_for_coverage_gcovr_xml(
    NAME
    coverage
    EXECUTABLE
    diamond-miner-tests
    EXCLUDE
    "${PROJECT_SOURCE_DIR}/extern/*"
    "${PROJECT_SOURCE_DIR}/src/*"
    "${PROJECT_SOURCE_DIR}/tests/*")
endif()

if(WITH_SANITIZER)
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined")
endif()

# Install
install(TARGETS diamond-miner-prober DESTINATION bin)
install(TARGETS diamond-miner-reader DESTINATION bin)
