#pragma once

#include <filesystem>
#include <iostream>

#include "../probe.hpp"
#include "../random_permutation.hpp"

namespace fs = std::filesystem;

void probe_from_csv(const std::string& line, Probe& probe);

// Classical reader

class CSVProbeIterator {
 public:
  CSVProbeIterator();
  CSVProbeIterator(const fs::path path);
  bool operator==(const CSVProbeIterator& other) const;
  bool operator!=(const CSVProbeIterator& other) const;
  const Probe& operator*() const;
  CSVProbeIterator& operator++();

 private:
  bool m_ended;
  Probe m_probe;
  std::unique_ptr<std::ifstream> m_stream;
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

// Random reader

class CSVRandomProbeIterator {
 public:
  CSVRandomProbeIterator();
  CSVRandomProbeIterator(const fs::path path, const int line_count,
                         const int line_size);
  bool operator==(const CSVRandomProbeIterator& other) const;
  bool operator!=(const CSVRandomProbeIterator& other) const;
  const Probe& operator*() const;
  CSVRandomProbeIterator& operator++();

 private:
  bool m_ended;
  Probe m_probe;
  std::unique_ptr<std::ifstream> m_stream;
  RandomPermutationIterator m_permutation;
  RandomPermutationIterator m_permutation_end;
  const int m_line_size;
  void next();
};

class CSVRandomProbeReader {
 public:
  CSVRandomProbeReader(const fs::path path, const int m_line_size);
  CSVRandomProbeIterator begin();
  CSVRandomProbeIterator end();

 private:
  const fs::path m_path;
  int m_line_count;
  int m_line_size;
};
