#include "csv.hpp"

#include <arpa/inet.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

#include "../probe.hpp"

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
  std::string token;

  if (std::getline(*m_stream, line)) {
    std::stringstream lstream{line};
    int index = 0;
    while (std::getline(lstream, token, ',')) {
      switch (index) {
        case 0:
          token = remove_leading_zeros(token);
          if (!inet_pton(AF_INET, token.c_str(), &m_probe.dst_addr)) {
            throw std::runtime_error("Invalid token: " + token);
          }
          break;
        case 1:
          m_probe.src_port = std::stoul(token);
          break;
        case 2:
          m_probe.dst_port = std::stoul(token);
          break;
        case 3:
          m_probe.ttl = std::stoul(token);
          break;
      }
      index++;
    }

    if (index != 4) {
      throw std::runtime_error("Invalid CSV line: " + line);
    }
  } else {
    m_ended = true;
  }
}

CSVProbeReader::CSVProbeReader(const fs::path path) : m_path(path){};
CSVProbeIterator CSVProbeReader::begin() { return CSVProbeIterator{m_path}; }
CSVProbeIterator CSVProbeReader::end() { return CSVProbeIterator{}; }
