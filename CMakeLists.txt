cmake_minimum_required(VERSION 3.12)
project(diamond-miner-prober VERSION 0.1.4)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(Boost REQUIRED COMPONENTS log log_setup program_options)
find_package(Catch2 REQUIRED)
find_package(Cperm REQUIRED)
find_package(Patricia REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(Tins REQUIRED IMPORTED_TARGET libtins)

option(WITH_PF_RING "Enable PF_RING support for sending packets" OFF)
configure_file(src/dminer_config.h.in dminer_config.h)

# Library
add_library(
  diamond-miner-prober-lib
  src/classic_sender_t.cpp
  src/heartbeat_t.cpp
  src/network_utils_t.cpp
  src/packets_utils.cpp
  src/parameters_utils_t.cpp
  src/rate_limiter.cpp
  src/sniffer_t.cpp
  src/timing_utils.cpp)

target_link_libraries(
  diamond-miner-prober-lib
  PUBLIC Boost::log
         Boost::log_setup
         Cperm::Cperm
         Patricia::Patricia
         PkgConfig::Tins
         Threads::Threads
         ZLIB::ZLIB)

target_compile_features(diamond-miner-prober-lib PUBLIC cxx_std_17)
target_compile_options(diamond-miner-prober-lib PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner-prober-lib
                           PUBLIC "${PROJECT_BINARY_DIR}")

# Executable
add_executable(diamond-miner-prober src/main.cpp)

target_link_libraries(
  diamond-miner-prober PUBLIC Boost::log Boost::log_setup
                              Boost::program_options diamond-miner-prober-lib)

target_compile_features(diamond-miner-prober PUBLIC cxx_std_17)
target_compile_options(diamond-miner-prober PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner-prober PUBLIC "${PROJECT_BINARY_DIR}")

if(WITH_PF_RING)
  find_package(PfRing REQUIRED)
  target_link_libraries(diamond-miner-prober PUBLIC PfRing::PfRing)
  target_sources(diamond-miner-prober PUBLIC src/pfring_sender_t.cpp)
endif()

# Tests
if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  include(Catch)
  include(CTest)
  add_executable(
    diamond-miner-prober-tests src/tests.cpp src/random_permutation_test.cpp
                               src/rate_limiter_test.cpp)
  target_link_libraries(diamond-miner-prober-tests
                        PUBLIC Catch2::Catch2 diamond-miner-prober-lib)
  target_compile_features(diamond-miner-prober-tests PUBLIC cxx_std_17)
  target_compile_options(diamond-miner-prober-tests PRIVATE -Wall -Wextra)
  catch_discover_tests(diamond-miner-prober-tests)
endif()

# Install
install(TARGETS diamond-miner-prober DESTINATION bin)
