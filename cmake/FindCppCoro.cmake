if(NOT TARGET CppCoro::CppCoro)
  add_library(CppCoro::CppCoro INTERFACE IMPORTED)
  # target_sources(CppCoro::CppCoro INTERFACE
  # "${PROJECT_SOURCE_DIR}/extern/cppcoro/...")
  target_include_directories(
    CppCoro::CppCoro INTERFACE "${PROJECT_SOURCE_DIR}/extern/cppcoro/include/")
endif()
