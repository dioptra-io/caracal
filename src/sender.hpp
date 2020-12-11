#pragma once

#include "probe.hpp"

class Sender {
 public:
  virtual void send(const Probe& probe, const int n_packets) = 0;
  virtual ~Sender() {}
};
