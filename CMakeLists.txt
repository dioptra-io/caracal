cmake_minimum_required(VERSION 3.12)
project(diamond-miner VERSION 0.1.10)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(Boost REQUIRED COMPONENTS log log_setup program_options)
find_package(Catch2 REQUIRED)
find_package(NetUtils REQUIRED)
find_package(Patricia REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(Tins REQUIRED IMPORTED_TARGET libtins)

option(WITH_TESTS "Build tests and enable coverage/sanitizer" OFF)
configure_file(src/diamond-miner-config.h.in diamond-miner-config.h)

# Library
add_library(diamond-miner INTERFACE)
target_compile_features(diamond-miner INTERFACE cxx_std_17)
target_compile_options(diamond-miner INTERFACE -DBOOST_LOG_DYN_LINK)
target_include_directories(diamond-miner
                           INTERFACE "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
  diamond-miner INTERFACE Boost::log Boost::log_setup NetUtils::NetUtils
                          Patricia::Patricia PkgConfig::Tins Threads::Threads)

# Executable (Prober)
add_executable(diamond-miner-prober src/diamond-miner-prober.cpp)
target_compile_options(diamond-miner-prober PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner-prober PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(diamond-miner-prober PRIVATE Boost::program_options
                                                   diamond-miner)

# Executable (Reader)
add_executable(diamond-miner-reader src/diamond-miner-reader.cpp)
target_compile_options(diamond-miner-reader PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner-reader PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(diamond-miner-reader PRIVATE Boost::program_options
                                                   diamond-miner)

# Tests
if(WITH_TESTS)
  include(Catch)
  include(CodeCoverage)
  include(CTest)

  file(GLOB TESTS_SOURCES tests/*.cpp)
  add_executable(diamond-miner-tests ${TESTS_SOURCES})
  target_compile_options(diamond-miner-tests PRIVATE -Wall -Wextra)
  target_link_libraries(diamond-miner-tests PRIVATE Catch2::Catch2
                                                    diamond-miner)

  # Coverage/sanitizer global flags
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")
  set(CMAKE_CXX_FLAGS
      "${CMAKE_CXX_FLAGS} -fsanitize=address -fsanitize=undefined")

  catch_discover_tests(diamond-miner-tests)
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

# Install
install(TARGETS diamond-miner-prober DESTINATION bin)
install(TARGETS diamond-miner-reader DESTINATION bin)
