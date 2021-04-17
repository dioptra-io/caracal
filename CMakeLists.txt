cmake_minimum_required(VERSION 3.12)

# We have Find* modules in two places:
# - The build directory, for the libraries fetched by Conan
# - The cmake/ directory, for the libraries not available with Conan
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

include(MunkeiVersionFromGit)
version_from_git(LOG ON)

project(caracal VERSION ${VERSION})

set(CARACAL_PRIVATE_FLAGS -Wall -Wextra -pedantic)
set(THREADS_PREFER_PTHREAD_FLAG ON)

file(GLOB CARACAL_LIBRARY_SOURCES src/*.cpp)
file(GLOB CARACAL_BENCH_SOURCES tests/*_bench.cpp)
file(GLOB CARACAL_TESTS_SOURCES tests/*_test.cpp)

option(WITH_COVERAGE "Enable code coverage" OFF)
option(WITH_LTO "Enable link time optimization" OFF)
option(WITH_SANITIZER "Enable compiler sanitizers" OFF)
configure_file(apps/caracal-config.h.in caracal-config.h)

find_package(Boost REQUIRED COMPONENTS program_options)
find_package(Catch2 REQUIRED)
find_package(Doxygen COMPONENTS dot)
find_package(libtins REQUIRED)
find_package(LPM REQUIRED)
find_package(NetUtils REQUIRED)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

include(Catch)
include(CTest)

# Library
add_library(caracal ${CARACAL_LIBRARY_SOURCES})
target_compile_features(caracal PUBLIC cxx_std_20)
target_compile_options(caracal PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_include_directories(caracal PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(
  caracal PRIVATE NetUtils::NetUtils spdlog::spdlog Threads::Threads
)
target_link_libraries(caracal PUBLIC libtins::libtins LPM::LPM)

# Executable (Prober)
add_executable(caracal-bin apps/caracal.cpp)
target_compile_options(caracal-bin PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_include_directories(caracal-bin PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(
  caracal-bin PRIVATE Boost::program_options spdlog::spdlog caracal
)
set_target_properties(caracal-bin PROPERTIES OUTPUT_NAME caracal)

# Executable (Reader)
add_executable(caracal-read apps/caracal-read.cpp)
target_compile_options(caracal-read PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_include_directories(caracal-read PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(
  caracal-read PRIVATE Boost::program_options spdlog::spdlog caracal
)

# Executable (Tests)
add_executable(caracal-test ${CARACAL_TESTS_SOURCES})
target_compile_options(caracal-test PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_link_libraries(
  caracal-test PRIVATE Catch2::Catch2WithMain NetUtils::NetUtils spdlog::spdlog
                       caracal
)
catch_discover_tests(caracal-test)

if(WITH_COVERAGE)
  include(CodeCoverage)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -fprofile-arcs -ftest-coverage")
  setup_target_for_coverage_gcovr_xml(
    NAME
    coverage
    EXECUTABLE
    caracal-test
    --benchmark-warmup-time
    0
    --benchmark-samples
    1
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

# Documentation
if(DOXYGEN_FOUND)
  doxygen_add_docs(caracal-docs "${PROJECT_SOURCE_DIR}/include/caracal")
endif()

# Install
install(TARGETS caracal-bin DESTINATION bin)
install(TARGETS caracal-read DESTINATION bin)
