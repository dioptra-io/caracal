#include "probe.hpp"

#include <arpa/inet.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace fs = std::filesystem;

std::ostream& operator<<(std::ostream& os, in_addr const& v) {
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &v, buf, INET_ADDRSTRLEN);
  os << buf;
  return os;
}

std::ostream& operator<<(std::ostream& os, Probe const& v) {
  os << "Probe{\"" << v.human_dst_addr() << "\", " << v.src_port << ", "
     << v.dst_port << ", " << uint(v.ttl) << "}";
  return os;
}

std::string Probe::human_dst_addr() const {
  char buf[INET_ADDRSTRLEN] = {};
  inet_ntop(AF_INET, &dst_addr, buf, INET_ADDRSTRLEN);
  return std::string{buf};
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

Probe& CSVProbeIterator::operator*() { return m_probe; }

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
