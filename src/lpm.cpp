#include <dminer/constants.hpp>
#include <dminer/lpm.hpp>
#include <fstream>

extern "C" {
#include <lpm.h>
}

namespace dminer {

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
  if (lpm_insert(lpm, &addr, len, preflen, tag) != 0) {
    throw std::runtime_error("LPM: failed to insert " + s);
  }
}

void LPM::insert(const in6_addr &addr, const uint32_t preflen) {
  int ret;
  if (IN6_IS_ADDR_V4MAPPED(&addr)) {
    ret = lpm_insert(lpm, &addr.s6_addr32[3], 4, preflen, tag);
  } else {
    ret = lpm_insert(lpm, &addr, 16, preflen, tag);
  }
  if (ret != 0) {
    throw std::runtime_error("LPM: failed to insert address");
  }
}

void LPM::insert_file(const fs::path &p) {
  if (!fs::exists(p)) {
    throw std::invalid_argument(p.string() + " does not exists");
  }
  std::ifstream f{p};
  std::string line;
  while (std::getline(f, line)) {
    insert(line);
  }
}

bool LPM::lookup(const std::string &s) {
  uint32_t addr[4];
  uint32_t preflen;
  size_t len;
  if (lpm_strtobin(s.c_str(), &addr, &len, &preflen) != 0) {
    throw std::runtime_error("LPM: failed to parse " + s);
  }
  return lpm_lookup(lpm, &addr, len) == tag;
}

bool LPM::lookup(const in6_addr &addr) {
  if (IN6_IS_ADDR_V4MAPPED(&addr)) {
    return lpm_lookup(lpm, &addr.s6_addr32[3], 4);
  } else {
    return lpm_lookup(lpm, &addr, 16);
  }
}

void *LPM::tag = (void *)0x42;

}  // namespace dminer