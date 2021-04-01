#pragma once

#include <span>

namespace caracal {

/// A structure holding pointers to the different layers of a packet buffer.
class Packet {
 public:
  Packet(std::span<std::byte> buffer, uint8_t l2_protocol, uint8_t l3_protocol,
         uint8_t l4_protocol, size_t payload_size);

  /// A pointer to the first byte of the packet (may include padding bytes).
  [[nodiscard]] std::byte *begin() const noexcept;

  /// A pointer past the last byte of the packet.
  [[nodiscard]] std::byte *end() const noexcept;

  /// A pointer to the first byte of the layer 2.
  [[nodiscard]] std::byte *l2() const noexcept;

  /// A pointer to the first byte of the layer 3.
  [[nodiscard]] std::byte *l3() const noexcept;

  /// A pointer to the first byte if the layer 4.
  [[nodiscard]] std::byte *l4() const noexcept;

  /// A pointer to the first byte of the payload.
  [[nodiscard]] std::byte *payload() const noexcept;

  /// Size of the packet starting from the L2 header.
  [[nodiscard]] size_t l2_size() const noexcept;

  /// Size of the packet starting from the L3 header.
  [[nodiscard]] size_t l3_size() const noexcept;

  /// Size of the packet starting from the L4 header.
  [[nodiscard]] size_t l4_size() const noexcept;

  /// Size of the packet starting from the payload.
  [[nodiscard]] size_t payload_size() const noexcept;

  /// Layer 2 protocol.
  [[nodiscard]] uint8_t l2_protocol() const noexcept;

  /// Layer 3 protocol.
  [[nodiscard]] uint8_t l3_protocol() const noexcept;

  /// Layer 4 protocol.
  [[nodiscard]] uint8_t l4_protocol() const noexcept;

 private:
  std::byte *begin_;
  std::byte *end_;
  std::byte *l2_;
  std::byte *l3_;
  std::byte *l4_;
  std::byte *payload_;
  uint8_t l2_protocol_;
  uint8_t l3_protocol_;
  uint8_t l4_protocol_;
};

}  // namespace caracal