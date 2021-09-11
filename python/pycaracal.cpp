#define PY_SSIZE_T_CLEAN

#include <pcap.h>
#include <pybind11/pybind11.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/spdlog.h>

#include <caracal/pretty.hpp>
#include <caracal/probe.hpp>
#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <caracal/protocols.hpp>
#include <memory>

#include "conversions.hpp"

namespace py = pybind11;
namespace Protocols = caracal::Protocols;
namespace Statistics = caracal::Statistics;

using caracal::Probe;
using caracal::Prober::Config;
using caracal::Prober::Iterator;
using caracal::Prober::probe;
using caracal::Prober::ProbingStatistics;

/// Proxy a Python `iterable` to a Prober `Iterator`.
ProbingStatistics py_probe(const Config& config, pybind11::iterable it) {
  auto cur = it.begin();
  auto end = it.end();
  Iterator iterator = [&](Probe& p) {
    if (cur == end) return false;
    p = (*cur++).cast<Probe>();
    return true;
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

Probe make_probe(const std::string& data, const uint16_t src_port,
                 const uint16_t dst_port, const uint8_t ttl,
                 const std::string& protocol) {
  Probe probe{};
  std::copy(data.begin(), data.end(), probe.dst_addr.s6_addr);
  probe.src_port = src_port;
  probe.dst_port = dst_port;
  probe.ttl = ttl;
  probe.protocol = Protocols::l4_from_string(protocol);
  return probe;
}

PYBIND11_MODULE(_pycaracal, m) {
  m.doc() = "Python bindings to a small subset of caracal.";

  m.def("make_probe", &make_probe);
  m.def("set_log_level", &set_log_level);

  py::class_<Probe>(m, "Probe")
      .def_readonly("dst_addr", &Probe::dst_addr)
      .def_readonly("src_port", &Probe::src_port)
      .def_readonly("dst_port", &Probe::dst_port)
      .def_readonly("ttl", &Probe::ttl)
      .def_readonly("protocol", &Probe::protocol)
      .def(py::init<in6_addr, uint16_t, uint16_t, uint8_t, Protocols::L4>())
      .def("from_csv", &Probe::from_csv)
      .def("to_csv", &Probe::to_csv)
      .def("__eq__", &Probe::operator==)
      .def("__str__", &fmt::to_string<Probe>);

  // pycaracal.prober
  auto m_prober = m.def_submodule("prober");
  // NOTE: The order is important here since a string is also an iterable.
  m_prober.def("probe",
               py::overload_cast<const Config&, const fs::path&>(&probe));
  m_prober.def("probe",
               py::overload_cast<const Config&, py::iterable>(&py_probe));

  py::class_<Config>(m_prober, "Config")
      .def(py::init<>())
      .def("set_caracal_id", &Config::set_caracal_id)
      .def("set_n_packets", &Config::set_n_packets)
      .def("set_probing_rate", &Config::set_probing_rate)
      .def("set_sniffer_wait_time", &Config::set_sniffer_wait_time)
      .def("set_integrity_check", &Config::set_integrity_check)
      .def("set_interface", &Config::set_interface)
      .def("set_rate_limiting_method", &Config::set_rate_limiting_method)
      .def("set_max_probes", &Config::set_max_probes)
      .def("set_output_file_csv", &Config::set_output_file_csv)
      .def("set_output_file_pcap", &Config::set_output_file_pcap)
      .def("set_prefix_excl_file", &Config::set_prefix_excl_file)
      .def("set_prefix_incl_file", &Config::set_prefix_incl_file)
      .def("set_filter_min_ttl", &Config::set_filter_min_ttl)
      .def("set_filter_max_ttl", &Config::set_filter_max_ttl)
      .def("set_meta_round", &Config::set_meta_round)
      .def("__str__", &fmt::to_string<Config>);

  // pycaracal.protocols
  auto m_proto = m.def_submodule("protocols");
  m_proto.def("l4_from_string", &Protocols::l4_from_string);
  py::enum_<Protocols::L4>(m_proto, "L4")
      .value("ICMP", Protocols::L4::ICMP)
      .value("ICMPv6", Protocols::L4::ICMPv6)
      .value("UDP", Protocols::L4::UDP)
      .export_values();

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

  py::class_<pcap_stat>(m_statistics, "PCAP")
      .def_readonly("received", &pcap_stat::ps_recv)
      .def_readonly("dropped", &pcap_stat::ps_drop)
      .def_readonly("interface_dropped", &pcap_stat::ps_ifdrop)
      .def("__str__", fmt::to_string<pcap_stat>);
}
