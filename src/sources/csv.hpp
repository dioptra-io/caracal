#pragma once

#include <algorithm>
#include <boost/iterator/iterator_facade.hpp>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

#include "../probe.hpp"
#include "../random_permutation.hpp"

namespace fs = std::filesystem;

// Quick hack from https://stackoverflow.com/a/966497,
// to make tests pass, since inet_pton returns an error
// on Linux when the address contains leading zeros.
// e.g. 008.008.008.008 => 8.8.8.8.
std::string remove_leading_zeros(std::string s) {
  std::replace(s.begin(), s.end(), '.', ' ');
  std::istringstream iss(s);
  int a, b, c, d;
  iss >> a >> b >> c >> d;
  std::ostringstream oss;
  oss << a << '.' << b << '.' << c << '.' << d;
  return oss.str();
}

void probe_from_csv(const std::string &line, Probe &probe) {
  std::stringstream lstream{line};
  std::string token;
  int index = 0;
  while (std::getline(lstream, token, ',')) {
    switch (index) {
      case 0:
        token = remove_leading_zeros(token);
        if (!inet_pton(AF_INET, token.c_str(), &probe.dst_addr)) {
          throw std::runtime_error("Invalid token: " + token);
        }
        break;
      case 1:
        probe.src_port = std::stoul(token);
        break;
      case 2:
        probe.dst_port = std::stoul(token);
        break;
      case 3:
        probe.ttl = std::stoul(token);
        break;
    }
    index++;
  }
  if (index != 4) {
    throw std::runtime_error("Invalid CSV line: " + line);
  }
}

class CSVProbeIterator
    : public boost::iterator_facade<CSVProbeIterator, Probe const,
                                    boost::forward_traversal_tag> {
 public:
  CSVProbeIterator() : m_stream{nullptr} {};

  explicit CSVProbeIterator(const fs::path path)
      : m_stream{std::make_unique<std::ifstream>(path)} {
    increment();
  }

 private:
  friend class boost::iterator_core_access;

  std::unique_ptr<std::ifstream> m_stream;
  std::string m_line;
  Probe m_probe;

  void increment() {
    if (!m_stream) {
      return;
    }
    if (std::getline(*m_stream, m_line)) {
      probe_from_csv(m_line, m_probe);
    } else {
      m_stream.reset();
    }
  }

  bool equal(CSVProbeIterator const &other) const {
    // TODO: Something cleaner?
    return m_stream == other.m_stream;
  }

  Probe const &dereference() const { return m_probe; }
};

class CSVProbeReader {
 public:
  CSVProbeReader(const fs::path path) : m_path(path) {}
  CSVProbeIterator begin() { return CSVProbeIterator{m_path}; }
  CSVProbeIterator end() { return CSVProbeIterator{}; }

 private:
  const fs::path m_path;
};

class CSVRandomProbeIterator
    : public boost::iterator_facade<CSVRandomProbeIterator, Probe const,
                                    boost::forward_traversal_tag> {
 public:
  CSVRandomProbeIterator() : m_stream(nullptr), m_line_size(0){};

  CSVRandomProbeIterator(const fs::path path, const int line_count,
                         const int line_size)
      : m_line_size(line_size),
        m_permutation{
            RandomPermutationIterator{static_cast<uint32_t>(line_count)}},
        m_permutation_end{RandomPermutationIterator{}},
        m_stream{std::make_unique<std::ifstream>(path)} {
    increment();
  }

 private:
  friend class boost::iterator_core_access;

  std::unique_ptr<std::ifstream> m_stream;
  RandomPermutationIterator m_permutation;
  RandomPermutationIterator m_permutation_end;
  const int m_line_size;
  std::string m_line;
  Probe m_probe;

  void increment() {
    if (m_permutation == m_permutation_end) {
      m_stream.reset();
      return;
    }
    (*m_stream).seekg(*m_permutation * m_line_size);
    std::getline(*m_stream, m_line);
    probe_from_csv(m_line, m_probe);
    std::advance(m_permutation, 1);
  }

  bool equal(CSVRandomProbeIterator const &other) const {
    // TODO: Something cleaner?
    return m_stream == other.m_stream;
  }

  Probe const &dereference() const { return m_probe; }
};

class CSVRandomProbeReader {
 public:
  CSVRandomProbeReader(const fs::path path, const int line_size)
      : m_path(path), m_line_size(line_size) {
    auto file_size = fs::file_size(path);
    if (file_size % line_size != 0) {
      throw std::runtime_error(
          "CSV file size is not a multiple of the line size");
    }
    m_line_count = file_size / line_size;
  };

  CSVRandomProbeIterator begin() {
    return CSVRandomProbeIterator{m_path, m_line_count, m_line_size};
  }
  CSVRandomProbeIterator end() { return CSVRandomProbeIterator{}; }

 private:
  const fs::path m_path;
  int m_line_count;
  int m_line_size;
};

// TODO: This is bad, deduplicate this code.
// Use a simple transform adaptator instead?
class CSVStdInProbeIterator
    : public boost::iterator_facade<CSVStdInProbeIterator, Probe const,
                                    std::input_iterator_tag> {
 public:
  CSVStdInProbeIterator(){};

 private:
  friend class boost::iterator_core_access;

  std::string m_line;
  Probe m_probe;

  void increment() {
    std::getline(std::cin, m_line);
    probe_from_csv(m_line, m_probe);
  }

  bool equal(CSVStdInProbeIterator const &other) const {
    // TODO: Something cleaner?
    return false;
  }

  Probe const &dereference() const { return m_probe; }
};

class CSVStdInProbeReader {
 public:
  CSVStdInProbeIterator begin() { return CSVStdInProbeIterator{}; }
  CSVStdInProbeIterator end() { return CSVStdInProbeIterator{}; }
};
