cmake_minimum_required(VERSION 3.16)

# We have Find* modules in two places:
# - The build directory, for the libraries fetched by Conan
# - The cmake/ directory, for the libraries not available with Conan
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

# Find the version from Git if `git` is installed and `.git/` is found.
# If not, the version will be set to `0.0.0`.
include(MunkeiVersionFromGit)
version_from_git(LOG ON)

project(caracal VERSION ${VERSION})

set(CARACAL_PRIVATE_FLAGS -Wall -Wextra -pedantic -fPIC)
set(THREADS_PREFER_PTHREAD_FLAG ON)

file(GLOB CARACAL_LIBRARY_SOURCES src/*.cpp)
file(GLOB CARACAL_BENCH_SOURCES tests/*_bench.cpp)
file(GLOB CARACAL_TESTS_SOURCES tests/*_test.cpp)

option(WITH_CONAN "Run conan install on configure" ON)
option(WITH_COVERAGE "Enable code coverage" OFF)
option(WITH_LTO "Enable link time optimization" OFF)
option(WITH_SANITIZER "Enable compiler sanitizers" OFF)
configure_file(apps/caracal-config.h.in caracal-config.h)

# Install the dependencies with conan, this is equivalent to `conan install ..`.
# Set this to `OFF` if you want to run conan manually or install the dependencies manually.
# If you install the dependencies manually (e.g. from source or using a package manager),
# you need to provide the relevant `Find*.cmake` modules in the CMake module path.
if(WITH_CONAN)
  include(conan)
  conan_cmake_autodetect(settings)
  # Set `arch=...` setting if the `CONAN_ARCH` env. variable is set.
  # This is useful to cross-compile on macOS, e.g. to compile for arm64:
  # CMAKE_OSX_ARCHITECTURES=arm64 CONAN_ARCH=armv8
  if(DEFINED ENV{CONAN_ARCH})
    set(settings ${settings} arch=$ENV{CONAN_ARCH})
  endif()
  conan_cmake_install(
    PATH_OR_REFERENCE
    ${CMAKE_CURRENT_SOURCE_DIR}
    BUILD
    b2
    missing
    SETTINGS
    ${settings}
    build_type=Release
    libtins:compiler.cppstd=11
  )
endif()

# Required packages
find_package(Boost REQUIRED)
find_package(Catch2 REQUIRED)
find_package(cxxopts REQUIRED)
find_package(libtins REQUIRED)
find_package(LPM REQUIRED)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

# Optional packages
find_package(pybind11)

include(Catch)
include(CTest)

# Library
add_library(caracal ${CARACAL_LIBRARY_SOURCES})
target_compile_features(caracal PUBLIC cxx_std_20)
target_compile_options(caracal PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_include_directories(caracal PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(caracal PRIVATE spdlog::spdlog LPM::LPM Threads::Threads)
# TODO: Remove boost and libtins from the public headers of caracal?
# In prober_config.hpp, sender.hpp, utilities.hpp.
target_link_libraries(caracal PUBLIC Boost::iostreams libtins::libtins)

# Executable (Prober)
add_executable(caracal-bin apps/caracal.cpp)
target_compile_options(caracal-bin PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_include_directories(caracal-bin PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(
  caracal-bin PRIVATE cxxopts::cxxopts spdlog::spdlog caracal
)
set_target_properties(caracal-bin PROPERTIES OUTPUT_NAME caracal)

# Executable (Tests)
add_executable(caracal-test ${CARACAL_TESTS_SOURCES})
target_compile_options(caracal-test PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_link_libraries(
  caracal-test PRIVATE Catch2::Catch2WithMain spdlog::spdlog caracal
)
catch_discover_tests(caracal-test)

# Python Module (pycaracal)
if(pybind11_FOUND)
  pybind11_add_module(_pycaracal MODULE python/pycaracal.cpp)
  target_link_libraries(_pycaracal PRIVATE caracal spdlog::spdlog)
  install(TARGETS _pycaracal LIBRARY DESTINATION .)
endif()

# Prevent scikit-build from building unneeded binaries.
if(SKBUILD)
  set_target_properties(caracal-bin caracal-test PROPERTIES EXCLUDE_FROM_ALL ON)
endif()

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
