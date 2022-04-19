#pragma once

#include <arpa/inet.h>
#include <pybind11/pybind11.h>

#include <algorithm>
#include <caracal/constants.hpp>
#include <filesystem>
#include <string>

namespace pybind11::detail {

template <>
struct type_caster<fs::path> {
 public:
  PYBIND11_TYPE_CASTER(fs::path, _("fs::path"));

  bool load(handle src, bool) {
    if (PyUnicode_Check(src.ptr())) {
      value = fs::path{src.cast<std::string>()};
      return true;
    }
    return false;
  }

  static handle cast(fs::path src, return_value_policy, handle) {
    return str(src.string());
  }
};

}  // namespace pybind11::detail
