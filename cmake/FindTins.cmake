set(LIBTINS_BUILD_SHARED
    OFF
    CACHE BOOL "Build libtins as a shared library." FORCE)
set(LIBTINS_BUILD_EXAMPLES
    OFF
    CACHE BOOL "Build examples" FORCE)
set(LIBTINS_BUILD_TESTS
    OFF
    CACHE BOOL "Build tests" FORCE)
set(LIBTINS_ENABLE_CXX11
    ON
    CACHE BOOL "Compile libtins with c++11 features" FORCE)
set(LIBTINS_ENABLE_WPA2
    OFF
    CACHE BOOL
          "Compile libtins with WPA2 decryption features (requires OpenSSL)"
          FORCE)
add_subdirectory(extern/libtins EXCLUDE_FROM_ALL)
target_include_directories(
  tins PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/extern/libtins/include>)
