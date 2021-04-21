#pragma once

#include <arpa/inet.h>
#include <pybind11/pybind11.h>

#include <algorithm>
#include <filesystem>
#include <string>

namespace pybind11::detail {

template <>
struct type_caster<in6_addr> {
 public:
  PYBIND11_TYPE_CASTER(in6_addr, _("in6_addr"));

  bool load(handle src, bool) {
    auto data =
        src.attr("__int__")().attr("to_bytes")(16, "big").cast<std::string>();
    std::copy(data.begin(), data.end(), value.s6_addr);
    return true;
  }

  static handle cast(in6_addr src, return_value_policy, handle) {
    // TODO: Return an integer instead.
    return PyBytes_FromStringAndSize(reinterpret_cast<char*>(src.s6_addr), 16);
  }
};

template <>
struct type_caster<fs::path> {
 public:
  PYBIND11_TYPE_CASTER(fs::path, _("fs::path"));

  bool load(handle src, bool) {
    value = fs::path{src.cast<std::string>()};
    return true;
  }

  static handle cast(fs::path src, return_value_policy, handle) {
    return str(src.string());
  }
};

}  // namespace pybind11::detail
