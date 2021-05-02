#pragma once

#include <cstdint>

/// Verify replies integrity.
namespace caracal::Integrity {

uint16_t checksum(uint32_t caracal_id, uint32_t dst_addr, uint16_t src_port,
                  uint8_t ttl);

}  // namespace caracal::Integrity
