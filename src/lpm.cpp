#include <caracal/constants.hpp>
#include <caracal/lpm.hpp>
#include <fstream>

extern "C" {
#include <lpm.h>
}

namespace caracal {

void ipv4_mapped_to_ipv4(uint32_t *addr, size_t *len, uint32_t *preflen) {
  // Internally LPM uses raw IPv4 and not IPv4-mapped IPv6 addresses.
  // TODO: Simplify this by implementing our own lpm_strtobin.
  if (IN6_IS_ADDR_V4MAPPED(reinterpret_cast<in6_addr *>(addr))) {
    addr[0] = addr[3];
    addr[1] = 0;
    addr[2] = 0;
    addr[3] = 0;
    *len = 4;
    if (*preflen == 128) {
      *preflen = 32;
    }
  }
}

LPM::LPM() {
  lpm = lpm_create();
  if (lpm == nullptr) {
    throw std::runtime_error("LPM: failed to create the structure");
  }
}

LPM::~LPM() { lpm_destroy(lpm); }

void LPM::insert(const std::string &s) {
  uint32_t addr[4];
  uint32_t preflen;
  size_t len;
  if (lpm_strtobin(s.c_str(), &addr, &len, &preflen) != 0) {
    throw std::runtime_error("LPM: failed to parse " + s);
  }
  ipv4_mapped_to_ipv4(addr, &len, &preflen);
  if (lpm_insert(lpm, &addr, len, preflen, tag) != 0) {
    throw std::runtime_error("LPM: failed to insert " + s);
  }
}

void LPM::insert_file(const fs::path &p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  std::ifstream f{p};
  std::string line;
  while (std::getline(f, line)) {
    if (!line.starts_with("#")) {
      insert(line);
    }
  }
}

bool LPM::lookup(const std::string &s) {
  uint32_t addr[4];
  uint32_t preflen;
  size_t len;
  if (lpm_strtobin(s.c_str(), &addr, &len, &preflen) != 0) {
    throw std::runtime_error("LPM: failed to parse " + s);
  }
  ipv4_mapped_to_ipv4(addr, &len, &preflen);
  return lpm_lookup(lpm, &addr, len) == tag;
}

bool LPM::lookup(const in6_addr &addr) {
  if (IN6_IS_ADDR_V4MAPPED(&addr)) {
    return lpm_lookup(lpm, &addr.s6_addr32[3], 4) == tag;
  } else {
    return lpm_lookup(lpm, &addr, 16) == tag;
  }
}

void *LPM::tag = reinterpret_cast<void *>(0x42);

}  // namespace caracal
