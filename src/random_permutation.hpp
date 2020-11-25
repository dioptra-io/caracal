#pragma once

#include <cperm.h>

#include <boost/iterator/iterator_facade.hpp>
#include <random>
#include <stdexcept>

class RandomPermutationIterator
    : public boost::iterator_facade<RandomPermutationIterator, uint32_t const,
                                    boost::forward_traversal_tag> {
 public:
  RandomPermutationIterator() : m_perm(nullptr), m_value(PERM_END) {}

  explicit RandomPermutationIterator(uint32_t range) {
    // TODO: Seeding.
    uint8_t key[16] = {static_cast<uint8_t>(rand() % 256)};

    // From yarrp code, to avoid slow permutation generation when range is
    // small.
    PermMode mode = PERM_MODE_CYCLE;
    if (range < 500000) {
      mode = PERM_MODE_PREFIX;
    }

    m_perm = cperm_create(range, mode, PERM_CIPHER_RC5, key, 16);
    if (m_perm == nullptr) {
      throw std::runtime_error("Failed to create permutation.");
    }

    increment();
  }

  ~RandomPermutationIterator() {
    if (m_perm != nullptr) {
      cperm_destroy(m_perm);
    }
  }

 private:
  friend class boost::iterator_core_access;

  cperm_t* m_perm;
  uint32_t m_value;

  void increment() {
    if (m_perm == nullptr) {
      return;
    }
    if (cperm_next(m_perm, &m_value) == PERM_END) {
      m_perm = nullptr;
      m_value = PERM_END;
    }
  }

  bool equal(RandomPermutationIterator const& other) const {
    return m_value == other.m_value;
  }

  uint32_t const& dereference() const { return m_value; }
};

class RandomPermutationGenerator {
 public:
  RandomPermutationGenerator() : m_range{1} {};
  explicit RandomPermutationGenerator(uint32_t range) {
    if (range < 1) {
      throw std::domain_error("range must be >= 1");
    }
    m_range = range;
  }

  RandomPermutationIterator begin() {
    return RandomPermutationIterator(m_range);
  }

  RandomPermutationIterator end() { return RandomPermutationIterator(); }

 private:
  uint32_t m_range;
};
