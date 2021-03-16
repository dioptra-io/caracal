if(NOT TARGET LPM::LPM)
  add_library(LPM::LPM INTERFACE IMPORTED)
  target_sources(LPM::LPM
                 INTERFACE "${PROJECT_SOURCE_DIR}/extern/liblpm/src/lpm.c")
  target_include_directories(
    LPM::LPM INTERFACE "${PROJECT_SOURCE_DIR}/extern/liblpm/src/")
endif()
