#pragma once

#include <arpa/inet.h>
#include <pybind11/pybind11.h>

#include <algorithm>
#include <caracal/constants.hpp>
#include <filesystem>
#include <string>

namespace pybind11::detail {

static const object IPv4Address =
    module_::import("ipaddress").attr("IPv4Address");
static const object IPv6Address =
    module_::import("ipaddress").attr("IPv6Address");

template <>
struct type_caster<in6_addr> {
 public:
  PYBIND11_TYPE_CASTER(in6_addr, _("in6_addr"));

  bool load(handle src, bool) {
    // Too slow... Optimize it in the future?
    if (PyLong_Check(src.ptr()) ||
        PyObject_IsInstance(src.ptr(), IPv6Address.ptr())) {
      auto data =
          src.attr("__int__")().attr("to_bytes")(16, "big").cast<std::string>();
      std::copy(data.begin(), data.end(), value.s6_addr);
      return true;
    }
    if (PyObject_IsInstance(src.ptr(), IPv4Address.ptr())) {
      value.s6_addr32[0] = 0;
      value.s6_addr32[1] = 0;
      value.s6_addr32[2] = 0xFFFF0000U;
      value.s6_addr32[3] = htonl(src.attr("__int__")().cast<uint32_t>());
      return true;
    }
    return false;
  }

  static handle cast(in6_addr src, return_value_policy, handle) {
    auto data = reinterpret_cast<char*>(src.s6_addr);
    return PyObject_CallFunction(IPv6Address.ptr(), "y#", data, 16);
  }
};

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
