#include <caracal/experimental.hpp>
#include <caracal/probe.hpp>
#include <caracal/prober_config.hpp>
#include <catch2/catch_test_macros.hpp>

using caracal::Probe;
using caracal::Experimental::Prober;
using caracal::Prober::Config;

TEST_CASE("Experimental::Prober") {
  Config config;
  config.interface = Config::get_default_interface();
  config.probing_rate = 100;
  config.caracal_id = 1;
  config.integrity_check = true;
  Prober prober{config, 1024 * 1024};
  std::vector<Probe> probes{{Probe::from_csv("8.8.8.8,24000,33434,32,icmp,1")}};
  std::function<void()> check_exception = []() {};
  prober.probe(probes, 100, check_exception);
}
