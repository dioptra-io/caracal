if(NOT TARGET Patricia::Patricia)
  find_package(ZLIB REQUIRED)
  add_library(Patricia::Patricia INTERFACE IMPORTED)
  target_sources(
    Patricia::Patricia
    INTERFACE "${PROJECT_SOURCE_DIR}/extern/patricia/patricia.cpp"
  )
  target_include_directories(
    Patricia::Patricia INTERFACE "${PROJECT_SOURCE_DIR}/extern/patricia/"
  )
  target_link_libraries(Patricia::Patricia INTERFACE ZLIB::ZLIB)
endif()
