#include <catch2/benchmark/catch_benchmark.hpp>
#include <catch2/catch_test_macros.hpp>
#include <dminer/probe.hpp>

using dminer::Probe;

TEST_CASE("Probe::from_csv") {
  BENCHMARK("IPv4 dotted") { return Probe::from_csv("0.0.0.0,1,2,3"); };

  BENCHMARK("IPv4 dotted and padded") {
    return Probe::from_csv("008.008.004.004,0010,1000,050");
  };

  BENCHMARK("IPv4 uint32") {
    return Probe::from_csv("134743044,0010,1000,050");
  };

  BENCHMARK("IPv4-mapped IPv6") {
    return Probe::from_csv("::ffff:8.8.4.4,10,1000,50");
  };

  BENCHMARK("IPv6") {
    return Probe::from_csv("2001:4860:4860::8888,10,1000,50");
  };
}
