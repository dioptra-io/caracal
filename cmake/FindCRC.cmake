if(NOT TARGET CRC::CRC)
    file(GLOB CRC_SOURCES "${PROJECT_SOURCE_DIR}/extern/libcrc/src/*.c")
    add_library(CRC::CRC INTERFACE IMPORTED)
    target_sources(CRC::CRC INTERFACE ${CRC_SOURCES})
    target_include_directories(
            CRC::CRC INTERFACE "${PROJECT_SOURCE_DIR}/extern/libcrc/include/")
endif()
