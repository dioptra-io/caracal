# Custom find-file for cperm which does not support cmake or pkg-config.
# - https://gitlab.kitware.com/cmake/community/-/wikis/doc/tutorials/How-To-Find-Libraries
# - https://dominikberner.ch/cmake-find-library/
project(Cperm LANGUAGES C)

add_library(
    Cperm
    ${PROJECT_SOURCE_DIR}/libcperm/src/cperm.c
    ${PROJECT_SOURCE_DIR}/libcperm/src/prefix.c
    ${PROJECT_SOURCE_DIR}/libcperm/src/cycle.c
    ${PROJECT_SOURCE_DIR}/libcperm/src/ciphers/rc5.c
    ${PROJECT_SOURCE_DIR}/libcperm/src/ciphers/rc5-16.c
    ${PROJECT_SOURCE_DIR}/libcperm/src/ciphers/speck.c
)

set_target_properties(
    Cperm
    PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/libcperm/src/"
)
