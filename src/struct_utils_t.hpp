#pragma once

#include <memory>
#include <utility>

namespace utils {
struct pair_hash {
  template <class T1, class T2>
  std::size_t operator()(const std::pair<T1, T2> &p) const {
    auto h1 = std::hash<T1>{}(p.first);
    auto h2 = std::hash<T2>{}(p.second);

    // Mainly for demonstration purposes, i.e. works but is overly simple
    // In the real world, use sth. like boost.hash_combine
    return h1 ^ h2;
  }
};

struct deref_hash {
  template <typename T>
  std::size_t operator()(std::shared_ptr<T> const &p) const {
    return std::hash<T>()(*p);
  }
};
struct deref_compare {
  template <typename T>
  size_t operator()(std::shared_ptr<T> const &a,
                    std::shared_ptr<T> const &b) const {
    return *a == *b;
  }
};

}  // namespace utils
