#pragma once

#include <pybind11/pybind11.h>
#include <spdlog/details/null_mutex.h>
#include <spdlog/sinks/base_sink.h>

#include <memory>
#include <mutex>
#include <string>

namespace py = pybind11;

template <typename Mutex>
class python_sink : public spdlog::sinks::base_sink<Mutex> {
 protected:
  void sink_it_(const spdlog::details::log_msg& msg) override {
    auto payload = msg.payload;
    auto str = std::string{payload.data(), payload.data() + payload.size()};
    switch (msg.level) {
      case spdlog::level::critical:
        py_logger_.attr("critical")(str);
        break;
      case spdlog::level::err:
        py_logger_.attr("error")(str);
        break;
      case spdlog::level::warn:
        py_logger_.attr("warning")(str);
        break;
      case spdlog::level::info:
        py_logger_.attr("info")(str);
        break;
      case spdlog::level::debug:
      case spdlog::level::trace:
        py_logger_.attr("debug")(str);
        break;
      default:
        break;
    }
  }

  void flush_() override {}

 private:
  py::object py_logger_ =
      py::module_::import("logging").attr("getLogger")("caracal");
};

using python_sink_mt = python_sink<std::mutex>;
using python_sink_st = python_sink<spdlog::details::null_mutex>;
