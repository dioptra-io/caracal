#include "random_permutation.hpp"

#include <cperm.h>

#include <cppcoro/generator.hpp>
#include <random>
#include <stdexcept>

cppcoro::generator<const uint32_t> random_permutation(uint32_t range) {
  if (range <= 0) {
    throw std::domain_error("range must be > 0");
  }
  // TODO: Seeding.
  uint8_t key[16] = {static_cast<uint8_t>(rand() % 256)};

  // From yarrp code, to avoid slow permutation generation when range is small.
  PermMode mode = PERM_MODE_CYCLE;
  if (range < 500000) {
    mode = PERM_MODE_PREFIX;
  }

  cperm_t* perm =
      cperm_create(range, PERM_MODE_PREFIX, PERM_CIPHER_RC5, key, 16);
  if (perm == NULL) {
    throw std::runtime_error("Failed to create permutation.");
  }

  uint32_t out;
  while (PERM_END != cperm_next(perm, &out)) {
    co_yield out;
  }

  cperm_destroy(perm);
}
