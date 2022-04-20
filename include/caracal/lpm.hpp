#pragma once

#include <netinet/in.h>

// Forward declaration to avoid including <lpm.h> in the public headers.
typedef struct lpm lpm_t;

#include <filesystem>
#include <string>
#include <tuple>

namespace fs = std::filesystem;

namespace caracal {

/// Longest Prefix Matching
class LPM {
 public:
  LPM();
  ~LPM();
  void insert(const std::string &s);
  void insert_file(const fs::path &p);
  bool lookup(const std::string &s);
  bool lookup(const in6_addr &addr);

 private:
  lpm_t *lpm;
  static void *tag;
};

}  // namespace caracal
