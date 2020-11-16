if(NOT TARGET Patricia::Patricia)
  add_library(Patricia::Patricia INTERFACE IMPORTED)
  target_sources(Patricia::Patricia
                 INTERFACE "${PROJECT_SOURCE_DIR}/extern/patricia/patricia.cpp")
  target_include_directories(Patricia::Patricia
                             INTERFACE "${PROJECT_SOURCE_DIR}/extern/patricia/")
endif()
