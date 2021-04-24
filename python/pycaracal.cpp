#include <pybind11/pybind11.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <caracal/probe.hpp>
#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <memory>

#include "conversions.hpp"
#include "logging.hpp"

namespace py = pybind11;
namespace Statistics = caracal::Statistics;

using caracal::Probe;
using caracal::Prober::Config;
using caracal::Prober::Iterator;
using caracal::Prober::probe;
using caracal::Prober::ProbingStatistics;

ProbingStatistics py_probe(Config& config, pybind11::iterable it) {
  auto cur = it.begin();
  auto end = it.end();
  if (cur == end) return ProbingStatistics{};
  Iterator iterator = [&](Probe& p) {
    p = (*cur).cast<Probe>();
    return (++cur != end);
  };
  return probe(config, iterator);
}

void set_log_level(int level) {
  if (level >= 50) {
    spdlog::set_level(spdlog::level::critical);
  } else if (level >= 40) {
    spdlog::set_level(spdlog::level::err);
  } else if (level >= 30) {
    spdlog::set_level(spdlog::level::warn);
  } else if (level >= 20) {
    spdlog::set_level(spdlog::level::info);
  } else if (level >= 10) {
    spdlog::set_level(spdlog::level::trace);
  }
}

PYBIND11_MODULE(_pycaracal, m) {
  m.doc() = "Python bindings to a small subset of caracal.";
  m.def("set_log_level", &set_log_level);

  py::class_<Probe>(m, "Probe")
      .def_readonly("dst_addr", &Probe::dst_addr)
      .def_readonly("src_port", &Probe::src_port)
      .def_readonly("dst_port", &Probe::dst_port)
      .def_readonly("ttl", &Probe::ttl)
      // TODO: Add protocol
      .def(py::init<in6_addr, uint16_t, uint16_t, uint8_t>())
      .def("from_csv", &Probe::from_csv)
      .def("to_csv", &Probe::to_csv)
      .def("__eq__", &Probe::operator==)
      .def("__str__", &fmt::to_string<Probe>);

  // pycaracal.prober
  auto m_prober = m.def_submodule("prober");
  m_prober.def("probe", &py_probe);

  py::class_<Config>(m_prober, "Config")
      .def(py::init<>())
      .def("set_output_file_csv", &Config::set_output_file_csv)
      .def("set_sniffer_wait_time", &Config::set_sniffer_wait_time);

  // pycaracal.statistics
  auto m_statistics = m.def_submodule("statistics");

  py::class_<Statistics::Prober>(m_statistics, "Prober")
      .def_readonly("read", &Statistics::Prober::read)
      .def_readonly("sent", &Statistics::Prober::sent)
      .def_readonly("failed", &Statistics::Prober::failed)
      .def_readonly("filtered_lo_ttl", &Statistics::Prober::filtered_lo_ttl)
      .def_readonly("filtered_hi_ttl", &Statistics::Prober::filtered_hi_ttl)
      .def_readonly("filtered_prefix_excl",
                    &Statistics::Prober::filtered_prefix_excl)
      .def_readonly("filtered_prefix_not_incl",
                    &Statistics::Prober::filtered_prefix_not_incl)
      .def("__str__", fmt::to_string<Statistics::Prober>);

  py::class_<Statistics::Sniffer>(m_statistics, "Sniffer")
      .def_readonly("received_count", &Statistics::Sniffer::received_count)
      .def_readonly("received_invalid_count",
                    &Statistics::Sniffer::received_invalid_count)
      .def("__str__", fmt::to_string<Statistics::Sniffer>);

  // Setup logging
  auto sink = std::make_shared<python_sink_mt>();
  auto logger = std::make_shared<spdlog::logger>("caracal", sink);
  spdlog::set_default_logger(logger);
}
