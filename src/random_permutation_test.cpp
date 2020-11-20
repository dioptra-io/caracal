#include "random_permutation.hpp"

#include <algorithm>
#include <catch2/catch.hpp>
#include <vector>

template <typename F>
std::vector<uint32_t> collect(F lambda) {
  std::vector<uint32_t> values;
  for (auto value : lambda()) {
    values.push_back(value);
  }
  return values;
}

TEST_CASE("RandomPermutationGenerator") {
  const int ranges[] = {1, 10, 100, 1000};
  for (auto range : ranges) {
    auto values =
        collect([range]() { return RandomPermutationGenerator(range); });
    REQUIRE(values.size() == range);
    REQUIRE(*std::min_element(values.begin(), values.end()) == 0);
    REQUIRE(*std::max_element(values.begin(), values.end()) == range - 1);
  }

  // It should not crash if we increment the iterator after the end;
  RandomPermutationGenerator gen{1};
  RandomPermutationIterator it = gen.begin();
  std::advance(it, 3);
}
