#pragma once

#include <filesystem>
#include <iostream>

#include "../probe.hpp"

namespace fs = std::filesystem;

class CSVProbeIterator {
 public:
  CSVProbeIterator();
  CSVProbeIterator(const fs::path path);
  ~CSVProbeIterator();
  bool operator==(const CSVProbeIterator& other) const;
  bool operator!=(const CSVProbeIterator& other) const;
  const Probe& operator*() const;
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
