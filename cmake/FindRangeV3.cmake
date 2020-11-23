if(NOT TARGET RangeV3::RangeV3)
  add_library(RangeV3::RangeV3 INTERFACE IMPORTED)
  target_include_directories(
    RangeV3::RangeV3 INTERFACE "${PROJECT_SOURCE_DIR}/extern/range-v3/include/")
endif()
