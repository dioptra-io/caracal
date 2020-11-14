add_library(
    Patricia
    ${PROJECT_SOURCE_DIR}/extern/patricia/patricia.cpp
)

set_target_properties(
    Patricia
    PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${PROJECT_SOURCE_DIR}/extern/patricia/"
)
