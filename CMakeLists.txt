cmake_minimum_required(VERSION 3.12)
project(diamond-miner VERSION 0.2.5)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

set(DMINER_PRIVATE_FLAGS -Wall -Wextra -pedantic)
set(THREADS_PREFER_PTHREAD_FLAG ON)

file(GLOB DMINER_LIBRARY_SOURCES src/*.cpp)
file(GLOB DMINER_BENCH_SOURCES tests/*_bench.cpp)
file(GLOB DMINER_TESTS_SOURCES tests/*_test.cpp)

option(WITH_COVERAGE "Enable code coverage" OFF)
option(WITH_LTO "Enable link time optimization" OFF)
option(WITH_SANITIZER "Enable compiler sanitizers" OFF)
configure_file(apps/diamond-miner-config.h.in diamond-miner-config.h)

find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Catch2 REQUIRED)
find_package(NetUtils REQUIRED)
find_package(Patricia REQUIRED)
find_package(spdlog REQUIRED)
find_package(Tins REQUIRED)
find_package(Threads REQUIRED)

include(Catch)
include(CTest)

# Library
add_library(diamond-miner ${DMINER_LIBRARY_SOURCES})
target_compile_features(diamond-miner PUBLIC cxx_std_20)
target_compile_options(diamond-miner PRIVATE ${DMINER_PRIVATE_FLAGS})
target_include_directories(diamond-miner PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
  diamond-miner PRIVATE NetUtils::NetUtils Patricia::Patricia spdlog::spdlog
                        Threads::Threads
)
target_link_libraries(diamond-miner PUBLIC tins)

# Executable (Prober)
add_executable(diamond-miner-prober apps/diamond-miner-prober.cpp)
target_compile_options(diamond-miner-prober PRIVATE ${DMINER_PRIVATE_FLAGS})
target_include_directories(diamond-miner-prober PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(
  diamond-miner-prober PRIVATE Boost::program_options spdlog::spdlog
                               diamond-miner
)

# Executable (Reader)
add_executable(diamond-miner-reader apps/diamond-miner-reader.cpp)
target_compile_options(diamond-miner-reader PRIVATE ${DMINER_PRIVATE_FLAGS})
target_include_directories(diamond-miner-reader PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(
  diamond-miner-reader PRIVATE Boost::program_options spdlog::spdlog
                               diamond-miner
)

# Executable (Benchmarks)
add_executable(diamond-miner-bench ${DMINER_BENCH_SOURCES})
target_compile_options(diamond-miner-bench PRIVATE ${DMINER_PRIVATE_FLAGS})
target_link_libraries(
  diamond-miner-bench PRIVATE Catch2::Catch2WithMain diamond-miner
)
catch_discover_tests(diamond-miner-bench)

# Executable (Tests)
add_executable(diamond-miner-tests ${DMINER_TESTS_SOURCES})
target_compile_options(diamond-miner-tests PRIVATE ${DMINER_PRIVATE_FLAGS})
target_link_libraries(
  diamond-miner-tests PRIVATE Catch2::Catch2WithMain NetUtils::NetUtils
                              spdlog::spdlog diamond-miner
)
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
    "${PROJECT_SOURCE_DIR}/apps/*"
    "${PROJECT_SOURCE_DIR}/extern/*"
    "${PROJECT_SOURCE_DIR}/tests/*"
  )
endif()

if(WITH_LTO)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -flto")
endif()

if(WITH_SANITIZER)
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined"
  )
endif()

# Install
install(TARGETS diamond-miner-prober DESTINATION bin)
install(TARGETS diamond-miner-reader DESTINATION bin)
