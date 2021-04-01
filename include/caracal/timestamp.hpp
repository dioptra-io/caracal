#pragma once

#include <chrono>

namespace caracal::Timestamp {

using tenth_ms = std::chrono::duration<uint64_t, std::ratio<1, 10000>>;

[[nodiscard]] uint16_t encode(uint64_t timestamp) noexcept;

[[nodiscard]] uint64_t decode(uint64_t timestamp, uint16_t remainder) noexcept;

[[nodiscard]] uint16_t difference(uint64_t timestamp,
                                  uint16_t remainder) noexcept;

template <typename Duration, typename TimePoint>
[[nodiscard]] uint64_t cast(TimePoint tp) noexcept {
  return std::chrono::duration_cast<Duration>(tp.time_since_epoch()).count();
}

}  // namespace caracal::Timestamp
