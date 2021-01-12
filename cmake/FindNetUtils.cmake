if(NOT TARGET NetUtils::NetUtils)
  add_library(NetUtils::NetUtils INTERFACE IMPORTED)
  target_sources(
    NetUtils::NetUtils
    INTERFACE "${PROJECT_SOURCE_DIR}/extern/libnetutils/checksum.c")
  target_include_directories(
    NetUtils::NetUtils
    INTERFACE "${PROJECT_SOURCE_DIR}/extern/libnetutils/include/")
endif()
