#pragma once

#include <netinet/in.h>

extern "C" {
#include <lpm.h>
}

#include <filesystem>
#include <string>
#include <tuple>

namespace fs = std::filesystem;

namespace caracal {

class LPM {
 public:
  LPM();
  ~LPM();
  void insert(const std::string &s);
  void insert(const in6_addr &addr, uint32_t preflen);
  void insert_file(const fs::path &p);
  bool lookup(const std::string &s);
  bool lookup(const in6_addr &addr);

 private:
  lpm_t *lpm;
  static void *tag;
};

}  // namespace caracal
