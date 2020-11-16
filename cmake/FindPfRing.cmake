find_library(PFRING_LIBRARY NAMES pfring libpfring)
find_path(PFRING_INCLUDE_DIR NAMES pfring.h)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PfRing DEFAULT_MSG PFRING_LIBRARY
                                  PFRING_INCLUDE_DIR)
mark_as_advanced(PFRING_LIBRARY PFRING_INCLUDE_DIR)

if(PFRING_FOUND AND NOT TARGET PfRing::PfRing)
  add_library(PfRing::PfRing SHARED IMPORTED)
  set_target_properties(
    PfRing::PfRing
    PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${PFRING_INCLUDE_DIR}"
               IMPORTED_LOCATION ${PFRING_LIBRARY})
endif()
