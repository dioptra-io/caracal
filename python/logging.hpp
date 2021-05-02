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
    // TODO: We tried to properly redirect the logs to the Python `logging`
    // module, but it segfaults when a message is logged by a different thread.
    py::print(str);
  }

  void flush_() override {}
};

using python_sink_mt = python_sink<std::mutex>;
using python_sink_st = python_sink<spdlog::details::null_mutex>;
