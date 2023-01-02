if(NOT TARGET bxzstr::bxzstr)
  add_library(bxzstr::bxzstr INTERFACE IMPORTED)
  target_include_directories(
    bxzstr::bxzstr INTERFACE "${PROJECT_SOURCE_DIR}/extern/bxzstr/include/")
endif()
