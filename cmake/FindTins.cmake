set(LIBTINS_BUILD_SHARED
    OFF
    CACHE BOOL "Build libtins as a shared library." FORCE)
add_subdirectory(extern/libtins EXCLUDE_FROM_ALL)
target_include_directories(
  tins PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/extern/libtins/include>)
