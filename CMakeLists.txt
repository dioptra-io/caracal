cmake_minimum_required(VERSION 3.16)
project(caracal VERSION 0.11.1)

# We have Find* modules in two places:
# - The build directory, for the libraries fetched by Conan
# - The cmake/ directory, for the libraries not available with Conan
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

set(CARACAL_PRIVATE_FLAGS -Wall -Wextra -pedantic -fPIC)
set(THREADS_PREFER_PTHREAD_FLAG ON)

file(GLOB CARACAL_LIBRARY_SOURCES src/*.cpp)
file(GLOB CARACAL_TESTS_SOURCES tests/*.cpp)

option(WITH_BINARY "Enable binary target" ON)
option(WITH_CONAN "Run conan install on configure" ON)
option(WITH_PYTHON "Enable Python target" ON)
option(WITH_TESTS "Enable tests target" ON)
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
find_package(Boost REQUIRED COMPONENTS iostreams)
find_package(libtins REQUIRED)
find_package(LPM REQUIRED)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

if(WITH_BINARY)
  find_package(cxxopts REQUIRED)
endif()

if(WITH_PYTHON)
  # Read an optional hint from the environment, used during CI to select the correct version on macOS.
  set(Python_ROOT_DIR $ENV{PYTHON_ROOT_DIR})
  message(STATUS "Python_ROOT_DIR: ${Python_ROOT_DIR}")
  find_package(
    Python
    COMPONENTS Development.Module Interpreter
    REQUIRED
  )
  find_package(pybind11 REQUIRED)
endif()

if(WITH_TESTS)
  find_package(Catch2 REQUIRED)
  include(Catch)
  include(CTest)
endif()

# If libtins is installed with conan, the `libtins::libtins` target is defined,
# but if libtins is installed with another package manager, the `tins` target is defined instead.
# To handle both cases we alias `tins` to `libtins::libtins`.
if(TARGET tins)
  add_library(libtins::libtins ALIAS tins)
endif()

add_library(caracal ${CARACAL_LIBRARY_SOURCES})
target_compile_features(caracal PUBLIC cxx_std_20)
target_compile_options(caracal PRIVATE ${CARACAL_PRIVATE_FLAGS})
target_include_directories(caracal PUBLIC "${PROJECT_SOURCE_DIR}/include")
target_link_libraries(caracal PRIVATE spdlog::spdlog LPM::LPM Threads::Threads)
# TODO: Remove boost and libtins from the public headers of caracal?
target_link_libraries(caracal PUBLIC Boost::iostreams libtins::libtins)

if(WITH_BINARY)
  add_executable(caracal-bin apps/caracal.cpp)
  target_compile_options(caracal-bin PRIVATE ${CARACAL_PRIVATE_FLAGS})
  target_include_directories(caracal-bin PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_libraries(
    caracal-bin PRIVATE cxxopts::cxxopts spdlog::spdlog caracal
  )
  set_target_properties(caracal-bin PROPERTIES OUTPUT_NAME caracal)
  install(TARGETS caracal-bin RUNTIME DESTINATION bin)
endif()

if(WITH_PYTHON)
  pybind11_add_module(_pycaracal MODULE python/pycaracal.cpp)
  target_link_libraries(_pycaracal PRIVATE caracal spdlog::spdlog)
  install(TARGETS _pycaracal LIBRARY DESTINATION .)
endif()

if(WITH_TESTS)
  add_executable(caracal-test ${CARACAL_TESTS_SOURCES})
  target_compile_definitions(
    caracal-test PRIVATE CATCH_CONFIG_ENABLE_BENCHMARKING
  )
  target_compile_options(caracal-test PRIVATE ${CARACAL_PRIVATE_FLAGS})
  target_link_libraries(
    caracal-test PRIVATE Catch2::Catch2 spdlog::spdlog caracal
  )
  catch_discover_tests(caracal-test)
endif()
