#include <caracal/pretty.hpp>
#include <catch2/catch.hpp>
#include <sstream>
#include <string>

template <typename T>
std::string to_string(T x) {
  std::stringstream ss;
  ss << x;
  return ss.str();
}

TEST_CASE("<< in_addr") {
  in_addr addr{};
  inet_pton(AF_INET, "8.8.4.4", &addr);
  REQUIRE(to_string(addr) == "8.8.4.4");

  sockaddr_in sa{};
  sa.sin_addr = addr;
  sa.sin_port = htons(24000);
  REQUIRE(to_string(sa) == "8.8.4.4:24000");
}

TEST_CASE("<< in6_addr") {
  in6_addr addr{};
  inet_pton(AF_INET6, "2001:4860:4860::8888", &addr);
  REQUIRE(to_string(addr) == "2001:4860:4860::8888");

  sockaddr_in6 sa{};
  sa.sin6_addr = addr;
  sa.sin6_port = htons(24000);
  REQUIRE(to_string(sa) == "[2001:4860:4860::8888]:24000");
}
