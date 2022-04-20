#include <caracal/experimental.hpp>
#include <caracal/probe.hpp>
#include <caracal/prober_config.hpp>
#include <catch2/catch.hpp>

using caracal::Probe;
using caracal::Experimental::Prober;
using caracal::Prober::Config;

TEST_CASE("Experimental::Prober") {
  Prober prober{Config::get_default_interface(), 100, 1024 * 1024, 1, true};
  std::vector<Probe> probes{{Probe::from_csv("8.8.8.8,24000,33434,32,icmp")}};
  std::function<void()> check_exception = []() {};
  prober.probe(probes, 100, check_exception);
}
