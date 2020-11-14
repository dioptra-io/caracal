cmake_minimum_required(VERSION 3.8)
project(diamond-miner-prober VERSION 0.1.4)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

set(Boost_USE_STATIC_LIBS OFF)
set(Boost_USE_MULTITHREADED ON)
set(Boost_USE_STATIC_RUNTIME OFF)
set(THREADS_PREFER_PTHREAD_FLAG TRUE)

find_package(Boost REQUIRED COMPONENTS log program_options)
find_package(Cperm REQUIRED)
find_package(Patricia REQUIRED)
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB REQUIRED)
pkg_check_modules(Tins REQUIRED IMPORTED_TARGET libtins)

option(USE_PF_RING "Use PF_RING to send packets" OFF)
configure_file(src/dminer_config.h.in dminer_config.h)

add_executable(
    diamond-miner-prober
    src/main.cpp
    src/classic_sender_t.cpp
    src/heartbeat_t.cpp
    src/sniffer_t.cpp
    src/network_utils_t.cpp
    src/packets_utils.cpp
    src/parameters_utils_t.cpp
    src/timing_utils.cpp
)

target_link_libraries(
    diamond-miner-prober PUBLIC
    Boost::log
    Boost::program_options
    Cperm
    Patricia
    PkgConfig::Tins
    Threads::Threads
    ZLIB::ZLIB
)

target_compile_features(diamond-miner-prober PUBLIC cxx_std_17)
target_compile_options(diamond-miner-prober PRIVATE -Wall -Wextra)
target_include_directories(diamond-miner-prober PUBLIC "${PROJECT_BINARY_DIR}")

if (USE_PF_RING)
    find_package(PfRing REQUIRED)
    target_link_libraries(diamond-miner-prober PUBLIC PfRing::PfRing)
    target_sources(diamond-miner-prober PUBLIC src/pfring_sender_t.cpp)
endif()

install(TARGETS diamond-miner-prober DESTINATION bin)

set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR "${diamond-miner-prober_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${diamond-miner-prober_VERSION_MINOR}")

include(InstallRequiredSystemLibraries)
include(CPack)
