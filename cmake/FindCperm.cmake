if(NOT TARGET Cperm::Cperm)
  add_library(Cperm::Cperm INTERFACE IMPORTED)
  target_sources(
    Cperm::Cperm
    INTERFACE "${PROJECT_SOURCE_DIR}/extern/libcperm/src/cperm.c"
              "${PROJECT_SOURCE_DIR}/extern/libcperm/src/prefix.c"
              "${PROJECT_SOURCE_DIR}/extern/libcperm/src/cycle.c"
              "${PROJECT_SOURCE_DIR}/extern/libcperm/src/ciphers/rc5.c"
              "${PROJECT_SOURCE_DIR}/extern/libcperm/src/ciphers/rc5-16.c"
              "${PROJECT_SOURCE_DIR}/extern/libcperm/src/ciphers/speck.c")
  target_include_directories(
    Cperm::Cperm INTERFACE "${PROJECT_SOURCE_DIR}/extern/libcperm/src/")
endif()
