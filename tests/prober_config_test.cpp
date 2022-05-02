#include <caracal/prober_config.hpp>
#include <catch2/catch.hpp>

using caracal::Prober::Config;

TEST_CASE("Prober::Config") {
  Config config{};
  REQUIRE_NOTHROW(config.set_caracal_id(0));
  REQUIRE_THROWS_AS(config.set_caracal_id(-1), std::domain_error);

  REQUIRE_NOTHROW(config.set_n_packets(1));
  REQUIRE_THROWS_AS(config.set_n_packets(0), std::domain_error);

  REQUIRE_NOTHROW(config.set_batch_size(1));
  REQUIRE_THROWS_AS(config.set_batch_size(0), std::domain_error);

  REQUIRE_NOTHROW(config.set_probing_rate(1));
  REQUIRE_THROWS_AS(config.set_probing_rate(0), std::domain_error);

  REQUIRE_NOTHROW(config.set_sniffer_wait_time(0));
  REQUIRE_THROWS_AS(config.set_sniffer_wait_time(-1), std::domain_error);

  REQUIRE_NOTHROW(config.set_integrity_check(true));
  REQUIRE_NOTHROW(config.set_integrity_check(false));

  REQUIRE_NOTHROW(config.set_interface("zzz"));

  REQUIRE_NOTHROW(config.set_rate_limiting_method("auto"));
  REQUIRE_NOTHROW(config.set_rate_limiting_method("active"));
  REQUIRE_NOTHROW(config.set_rate_limiting_method("sleep"));
  REQUIRE_NOTHROW(config.set_rate_limiting_method("none"));
  REQUIRE_THROWS_AS(config.set_rate_limiting_method("zzz"),
                    std::invalid_argument);

  REQUIRE_NOTHROW(config.set_max_probes(1));
  REQUIRE_THROWS_AS(config.set_max_probes(0), std::domain_error);

  REQUIRE_NOTHROW(config.set_output_file_csv("zzz"));
  REQUIRE_NOTHROW(config.set_output_file_pcap("zzz"));

  REQUIRE_THROWS_AS(config.set_prefix_excl_file("zzz"), std::invalid_argument);
  REQUIRE_THROWS_AS(config.set_prefix_incl_file("zzz"), std::invalid_argument);

  REQUIRE_NOTHROW(config.set_filter_min_ttl(0));
  REQUIRE_THROWS_AS(config.set_filter_min_ttl(-1), std::domain_error);

  REQUIRE_NOTHROW(config.set_filter_max_ttl(0));
  REQUIRE_THROWS_AS(config.set_filter_max_ttl(-1), std::domain_error);

  REQUIRE_NOTHROW(config.set_meta_round("zzz"));
}
