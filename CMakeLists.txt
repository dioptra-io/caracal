cmake_minimum_required(VERSION 3.16)
project(caracal VERSION 0.15.2)

# We have Find* modules in two places:
# - The build directory, for the libraries fetched by Conan
# - The cmake/ directory, for the libraries not available with Conan
list(APPEND CMAKE_MODULE_PATH ${CMAKE_BINARY_DIR})
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake/)

set(CARACAL_PRIVATE_FLAGS -Wall -Wextra -pedantic)
set(THREADS_PREFER_PTHREAD_FLAG ON)

file(GLOB CARACAL_LIBRARY_SOURCES src/*.cpp)
file(GLOB CARACAL_TESTS_SOURCES tests/*.cpp)

option(WITH_BINARY "Enable binary target" OFF)
option(WITH_CONAN "Run conan install on configure" OFF)
option(WITH_TESTS "Enable tests target" OFF)
configure_file(apps/caracal-config.h.in caracal-config.h)

# Install the dependencies with conan, this is equivalent to `conan install ..`.
# Set this to `OFF` if you want to run conan manually or install the dependencies manually.
# If you install the dependencies manually (e.g. from source or using a package manager),
# you need to provide the relevant `Find*.cmake` modules in the CMake module path.
if(WITH_CONAN)
  include(conan)
  conan_cmake_autodetect(settings)
  conan_cmake_install(
    PATH_OR_REFERENCE
    ${CMAKE_CURRENT_SOURCE_DIR}
    BUILD
    missing
    SETTINGS
    ${settings}
    build_type=Release
    libtins:compiler.cppstd=11
  )
endif()

# Required packages
find_package(libtins REQUIRED)
find_package(LPM REQUIRED)
find_package(spdlog REQUIRED)
find_package(Threads REQUIRED)

if(WITH_BINARY)
  find_package(cxxopts REQUIRED)
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
target_link_libraries(
  caracal PRIVATE spdlog::spdlog LPM::LPM Threads::Threads
)
# TODO: Remove libtins from the public headers of caracal?
target_link_libraries(caracal PUBLIC libtins::libtins)

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

if(WITH_TESTS)
  add_executable(caracal-test ${CARACAL_TESTS_SOURCES})
  target_compile_definitions(
    caracal-test PRIVATE CATCH_CONFIG_ENABLE_BENCHMARKING
  )
  target_compile_options(caracal-test PRIVATE ${CARACAL_PRIVATE_FLAGS})
  target_link_libraries(
    caracal-test PRIVATE Catch2::Catch2WithMain spdlog::spdlog caracal
  )
  catch_discover_tests(caracal-test)
endif()
