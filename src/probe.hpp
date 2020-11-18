#pragma once

#include <arpa/inet.h>

#include <filesystem>
#include <iostream>

namespace fs = std::filesystem;

struct Probe {
  in_addr dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t ttl;
  std::string human_dst_addr() const;
};

std::ostream& operator<<(std::ostream& os, in_addr const& v);
std::ostream& operator<<(std::ostream& os, Probe const& v);

class CSVProbeIterator {
 public:
  CSVProbeIterator();
  CSVProbeIterator(const fs::path path);
  ~CSVProbeIterator();
  bool operator==(const CSVProbeIterator& other) const;
  bool operator!=(const CSVProbeIterator& other) const;
  Probe& operator*();
  CSVProbeIterator& operator++();

 private:
  bool m_ended;
  Probe m_probe;
  std::ifstream* m_stream;
  void next();
};

class CSVProbeReader {
 public:
  CSVProbeReader(const fs::path path);
  CSVProbeIterator begin();
  CSVProbeIterator end();

 private:
  const fs::path m_path;
};
