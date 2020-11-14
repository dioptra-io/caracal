add_library(
    Cperm
    ${PROJECT_SOURCE_DIR}/extern/libcperm/src/cperm.c
    ${PROJECT_SOURCE_DIR}/extern/libcperm/src/prefix.c
    ${PROJECT_SOURCE_DIR}/extern/libcperm/src/cycle.c
    ${PROJECT_SOURCE_DIR}/extern/libcperm/src/ciphers/rc5.c
    ${PROJECT_SOURCE_DIR}/extern/libcperm/src/ciphers/rc5-16.c
    ${PROJECT_SOURCE_DIR}/extern/libcperm/src/ciphers/speck.c
)

set_target_properties(
    Cperm
    PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/extern/libcperm/src/"
)
