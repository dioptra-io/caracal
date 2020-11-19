#include "csv.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

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

void probe_from_csv(const std::string& line, Probe& probe) {
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

// Classical reader

CSVProbeIterator::CSVProbeIterator() : m_ended(true), m_stream(NULL){};

CSVProbeIterator::CSVProbeIterator(const fs::path path) : m_ended(false) {
  m_stream = new std::ifstream{path};
  next();
}

CSVProbeIterator::~CSVProbeIterator() { delete m_stream; }

bool CSVProbeIterator::operator==(const CSVProbeIterator& other) const {
  return (m_ended && other.m_ended);
}

bool CSVProbeIterator::operator!=(const CSVProbeIterator& other) const {
  return !(*this == other);
}

const Probe& CSVProbeIterator::operator*() const { return m_probe; }

CSVProbeIterator& CSVProbeIterator::operator++() {
  next();
  return *this;
}

void CSVProbeIterator::next() {
  std::string line;
  if (std::getline(*m_stream, line)) {
    probe_from_csv(line, m_probe);
  } else {
    m_ended = true;
  }
}

CSVProbeReader::CSVProbeReader(const fs::path path) : m_path(path){};
CSVProbeIterator CSVProbeReader::begin() { return CSVProbeIterator{m_path}; }
CSVProbeIterator CSVProbeReader::end() { return CSVProbeIterator{}; }

// Random reader

CSVRandomProbeIterator::CSVRandomProbeIterator()
    : m_ended(true), m_stream(NULL), m_line_size(0){};

CSVRandomProbeIterator::CSVRandomProbeIterator(const fs::path path,
                                               const int line_count,
                                               const int line_size)
    : m_ended(false),
      m_line_size(line_size),
      m_permutation{
          RandomPermutationIterator{static_cast<uint32_t>(line_count)}},
      m_permutation_end{RandomPermutationIterator{}} {
  m_stream = new std::ifstream{path};
  next();
}

CSVRandomProbeIterator::~CSVRandomProbeIterator() { delete m_stream; }

bool CSVRandomProbeIterator::operator==(
    const CSVRandomProbeIterator& other) const {
  return (m_ended && other.m_ended);
}

bool CSVRandomProbeIterator::operator!=(
    const CSVRandomProbeIterator& other) const {
  return !(*this == other);
}

const Probe& CSVRandomProbeIterator::operator*() const { return m_probe; }

CSVRandomProbeIterator& CSVRandomProbeIterator::operator++() {
  next();
  return *this;
}

void CSVRandomProbeIterator::next() {
  // std::cout << "Hello " << (m_file_size / m_line_size) << std::endl;
  // TODO: Make a proper input iterator.
  // std::next(m_permutation);
  if (m_permutation == m_permutation_end) {
    m_ended = true;
    return;
  }
  (*m_stream).seekg(*m_permutation * m_line_size);
  std::string line;
  std::getline(*m_stream, line);
  probe_from_csv(line, m_probe);
  ++m_permutation;
}

// TODO: auto-detect line size?
CSVRandomProbeReader::CSVRandomProbeReader(const fs::path path,
                                           const int line_size)
    : m_path(path), m_line_size(line_size) {
  auto file_size = fs::file_size(path);
  if (file_size % line_size != 0) {
    throw std::runtime_error(
        "CSV file size is not a multiple of the line size");
  }
  m_line_count = file_size / line_size;
};

CSVRandomProbeIterator CSVRandomProbeReader::begin() {
  return CSVRandomProbeIterator{m_path, m_line_count, m_line_size};
}
CSVRandomProbeIterator CSVRandomProbeReader::end() {
  return CSVRandomProbeIterator{};
}
