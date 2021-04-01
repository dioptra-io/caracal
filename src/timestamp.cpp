#include <caracal/timestamp.hpp>
#include <chrono>
#include <cmath>

namespace caracal::Timestamp {

uint16_t encode(uint64_t timestamp) noexcept {
  return static_cast<uint16_t>(timestamp % 65535);
}

uint64_t decode(uint64_t timestamp, uint16_t remainder) noexcept {
  uint64_t quotient = std::ceil(timestamp / 65535.0) - 1;
  uint64_t decoded = quotient * 65535 + remainder;
  return decoded > timestamp ? decoded - 65535 : decoded;
}

uint16_t difference(uint64_t timestamp, uint16_t remainder) noexcept {
  return static_cast<uint16_t>(timestamp - decode(timestamp, remainder));
}

}  // namespace caracal::Timestamp
