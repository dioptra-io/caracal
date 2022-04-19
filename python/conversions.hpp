#pragma once

#include <arpa/inet.h>
#include <pybind11/pybind11.h>

#include <algorithm>
#include <caracal/constants.hpp>
#include <filesystem>
#include <string>

#include "caracal/protocols.hpp"

namespace Protocols = caracal::Protocols;

namespace pybind11::detail {

template <>
struct type_caster<in6_addr> {
 public:
  PYBIND11_TYPE_CASTER(in6_addr, _("in6_addr"));

  bool load(handle src, bool) {
    if (PyLong_Check(src.ptr())) {
      auto data =
          src.attr("__int__")().attr("to_bytes")(16, "big").cast<std::string>();
      std::copy(data.begin(), data.end(), value.s6_addr);
      return true;
    }
    if (PyUnicode_Check(src.ptr())) {
      caracal::Utilities::parse_addr(src.cast<std::string>(), value);
      return true;
    }
    return false;
  }

  static handle cast(in6_addr src, return_value_policy, handle) {
    auto data = caracal::Utilities::format_addr(src);
    return PyUnicode_FromString(data.c_str());
  }
};

template <>
struct type_caster<Protocols::L4> {
 public:
  PYBIND11_TYPE_CASTER(Protocols::L4, _("Protocols::L4"));

  bool load(handle src, bool) {
    if (PyUnicode_Check(src.ptr())) {
      value = Protocols::l4_from_string(src.cast<std::string>());
      return true;
    }
    return false;
  }

  static handle cast(Protocols::L4 src, return_value_policy, handle) {
    return PyUnicode_FromString(Protocols::to_string(src).c_str());
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
