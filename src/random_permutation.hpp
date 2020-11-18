#pragma once

#include <cperm.h>

#include <random>
#include <stdexcept>

class RandomPermutationIterator {
 public:
  RandomPermutationIterator(uint32_t range) {
    // TODO: Seeding.
    uint8_t key[16] = {static_cast<uint8_t>(rand() % 256)};

    // From yarrp code, to avoid slow permutation generation when range is
    // small.
    PermMode mode = PERM_MODE_CYCLE;
    if (range < 500000) {
      mode = PERM_MODE_PREFIX;
    }

    m_perm = cperm_create(range, PERM_MODE_PREFIX, PERM_CIPHER_RC5, key, 16);
    if (m_perm == NULL) {
      throw std::runtime_error("Failed to create permutation.");
    }

    next();
  }

  RandomPermutationIterator(cperm_t* perm, uint32_t value)
      : m_perm(perm), m_value(value) {}

  ~RandomPermutationIterator() { cperm_destroy(m_perm); }

  bool operator==(const RandomPermutationIterator& other) const {
    return (m_perm == other.m_perm) && (m_value == other.m_value);
  }

  bool operator!=(const RandomPermutationIterator& other) const {
    return !(*this == other);
  }

  uint32_t operator*() const { return m_value; }

  RandomPermutationIterator& operator++() {
    next();
    return *this;
  }

 private:
  cperm_t* m_perm;
  uint32_t m_value;

  void next() {
    int status = cperm_next(m_perm, &m_value);
    if (status == PERM_END) {
      m_perm = NULL;
      m_value = PERM_END;
    }
  }
};

class RandomPermutationGenerator {
 public:
  RandomPermutationGenerator(uint32_t range) {
    if (range <= 0) {
      throw std::domain_error("range must be > 0");
    }
    m_range = range;
  }

  RandomPermutationIterator begin() {
    return RandomPermutationIterator(m_range);
  }

  RandomPermutationIterator end() {
    return RandomPermutationIterator(NULL, PERM_END);
  }

 private:
  uint32_t m_range;
};
