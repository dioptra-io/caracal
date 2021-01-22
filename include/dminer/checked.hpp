#pragma once

#include <arpa/inet.h>

#include <limits>

/// Checked versions of common functions, that raise an exception on incorrect
/// usage.
// TODO: Benchmark the performance impact of this with a CHECKED define.
namespace dminer::Checked {

template <typename Type, typename Value>
[[nodiscard]] inline constexpr Type cast(const Value value) {
  // Compile-time fast-path if Value is included into Type.
  if ((std::numeric_limits<Value>::min() >= std::numeric_limits<Type>::min()) &&
      (std::numeric_limits<Value>::max() <= std::numeric_limits<Type>::max())) {
    return static_cast<Type>(value);
  }
  // Runtime check otherwise.
  if ((value >= std::numeric_limits<Type>::min()) &&
      (value <= std::numeric_limits<Type>::max())) {
    return static_cast<Type>(value);
  }
  throw std::invalid_argument{
      "Value (" + std::to_string(value) + ") must be between " +
      std::to_string(std::numeric_limits<Type>::min()) + " and " +
      std::to_string(std::numeric_limits<Type>::max())};
}

template <typename Value>
[[nodiscard]] inline constexpr uint16_t htons(const Value value) {
  return ::htons(cast<uint16_t>(value));
}

template <typename Value>
[[nodiscard]] inline constexpr uint32_t htonl(const Value value) {
  return ::htonl(cast<uint32_t>(value));
}

}  // namespace dminer::Checked
