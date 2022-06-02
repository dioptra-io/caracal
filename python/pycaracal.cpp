#define PY_SSIZE_T_CLEAN

#include <pcap.h>
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/fmt/ostr.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/spdlog.h>

#include <caracal/experimental.hpp>
#include <caracal/pretty.hpp>
#include <caracal/probe.hpp>
#include <caracal/prober.hpp>
#include <caracal/prober_config.hpp>
#include <caracal/protocols.hpp>
#include <caracal/reply.hpp>
#include <caracal/utilities.hpp>
#include <memory>

#include "./conversions.hpp"

namespace py = pybind11;
namespace Experimental = caracal::Experimental;
namespace Protocols = caracal::Protocols;
namespace Statistics = caracal::Statistics;
namespace Utilities = caracal::Utilities;

using caracal::Probe;
using caracal::Reply;
using caracal::Prober::Config;
using caracal::Prober::Iterator;
using caracal::Prober::probe;
using caracal::Prober::ProbingStatistics;
using pybind11::literals::operator"" _a;

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

class ProberWrapper {
 public:
  ProberWrapper(const std::string& interface, uint64_t probing_rate,
                uint64_t buffer_size, uint16_t caracal_id, bool integrity_check)
      : prober_{interface, probing_rate, buffer_size, caracal_id,
                integrity_check} {};

  std::vector<Reply> probe(const std::vector<Probe>& probes,
                           uint64_t timeout_ms) {
    std::function<void()> check_exception = [&]() {
      if (PyErr_CheckSignals() != 0) {
        throw py::error_already_set();
      }
    };
    return prober_.probe(probes, timeout_ms, check_exception);
  }

 private:
  Experimental::Prober prober_;
};

template <typename T>
auto repr(const std::string& name) {
  return [name](const T& v) { return fmt::format("{}({})", name, v); };
}

PYBIND11_MODULE(_pycaracal, m) {
  m.doc() = "Python bindings to a small subset of caracal.";

  m.def("log_to_stderr", []() {
    spdlog::set_default_logger(spdlog::stderr_logger_st("dummy"));
    spdlog::set_default_logger(spdlog::stderr_logger_st(""));
  });

  m.def(
      "set_log_format",
      [](const std::string& pattern) { spdlog::set_pattern(pattern); },
      "pattern"_a);

  m.def(
      "set_log_level",
      [](int level) {
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
      },
      "level"_a);

  py::class_<Probe>(m, "Probe")
      .def(py::init<>())
      .def(py::init<in6_addr, uint16_t, uint16_t, uint8_t, Protocols::L4,
                    uint32_t>(),
           "dst_addr"_a, "src_port"_a, "dst_port"_a, "ttl"_a, "protocol"_a,
           "wait_us"_a)
      .def_readwrite("dst_addr", &Probe::dst_addr)
      .def_readwrite("src_port", &Probe::src_port)
      .def_readwrite("dst_port", &Probe::dst_port)
      .def_readwrite("ttl", &Probe::ttl)
      .def_readwrite("protocol", &Probe::protocol)
      .def_readwrite("wait_us", &Probe::wait_us)
      .def("__eq__", &Probe::operator==)
      .def("__repr__", repr<Probe>("Probe"));

  py::class_<Reply>(m, "Reply")
      .def(py::init<>())
      .def_readwrite("capture_timestamp", &Reply::capture_timestamp)
      .def_readwrite("reply_src_addr", &Reply::reply_src_addr)
      .def_readwrite("reply_dst_addr", &Reply::reply_dst_addr)
      .def_readwrite("reply_id", &Reply::reply_id)
      .def_readwrite("reply_size", &Reply::reply_size)
      .def_readwrite("reply_ttl", &Reply::reply_ttl)
      .def_readwrite("reply_protocol", &Reply::reply_protocol)
      .def_readwrite("reply_icmp_type", &Reply::reply_icmp_type)
      .def_readwrite("reply_icmp_code", &Reply::reply_icmp_code)
      .def_readwrite("reply_mpls_labels", &Reply::reply_mpls_labels)
      .def_readwrite("probe_dst_addr", &Reply::probe_dst_addr)
      .def_readwrite("probe_id", &Reply::probe_id)
      .def_readwrite("probe_size", &Reply::probe_size)
      .def_readwrite("probe_protocol", &Reply::probe_protocol)
      .def_readwrite("quoted_ttl", &Reply::quoted_ttl)
      .def_readwrite("probe_src_port", &Reply::probe_src_port)
      .def_readwrite("probe_dst_port", &Reply::probe_dst_port)
      .def_readwrite("probe_ttl", &Reply::probe_ttl)
      .def_readwrite("rtt", &Reply::rtt)
      .def_property_readonly("destination_unreachable",
                             &Reply::is_destination_unreachable)
      .def_property_readonly("echo_reply", &Reply::is_echo_reply)
      .def_property_readonly("time_exceeded", &Reply::is_time_exceeded)
      .def("__repr__", repr<Reply>("Reply"));

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
      .def("set_batch_size", &Config::set_batch_size)
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
      .def("__repr__", repr<Config>("Config"));

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
      .def("__repr__", repr<Statistics::Prober>("statistics.Prober"));

  py::class_<Statistics::Sniffer>(m_statistics, "Sniffer")
      .def_readonly("received_count", &Statistics::Sniffer::received_count)
      .def_readonly("received_invalid_count",
                    &Statistics::Sniffer::received_invalid_count)
      .def("__repr__", repr<Statistics::Sniffer>("statistics.Sniffer"));

  py::class_<pcap_stat>(m_statistics, "PCAP")
      .def_readonly("received", &pcap_stat::ps_recv)
      .def_readonly("dropped", &pcap_stat::ps_drop)
      .def_readonly("interface_dropped", &pcap_stat::ps_ifdrop)
      .def("__repr__", repr<pcap_stat>("statistics.PCAP"));

  // pycaracal.utilities
  auto m_utilities = m.def_submodule("utilities");
  m_utilities.def("get_default_interface", &Config::get_default_interface);
  m_utilities.def(
      "source_ipv4_for",
      [](const std::string& interface_name) {
        return Utilities::source_ipv4_for(interface_name).to_string();
      },
      "interface_name"_a);
  m_utilities.def(
      "source_ipv6_for",
      [](const std::string& interface_name) {
        return Utilities::source_ipv6_for(interface_name).to_string();
      },
      "interface_name"_a);

  // pycaracal.experimental
  auto m_experimental = m.def_submodule("experimental");
  py::class_<ProberWrapper>(m_experimental, "Prober")
      .def(py::init<std::string, uint64_t, uint64_t, uint16_t, bool>())
      .def("probe", &ProberWrapper::probe);
}
