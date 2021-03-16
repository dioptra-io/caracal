add_subdirectory(extern/Catch2 EXCLUDE_FROM_ALL)
list(APPEND CMAKE_MODULE_PATH
     "${CMAKE_CURRENT_SOURCE_DIR}/extern/Catch2/extras"
)
