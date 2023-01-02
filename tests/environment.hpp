#pragma once
#include <cstdlib>

// Enable IPv6 tests on demand.
const bool has_ipv6 = std::getenv("IPV6") != nullptr;

// Detect GitHub actions and skip tests that require precise timing
// or unfiltered network access.
const bool is_github = std::getenv("CI") != nullptr;

#ifdef __APPLE__
const bool is_macos = true;
#else
const bool is_macos = false;
#endif
