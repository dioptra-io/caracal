#pragma once

#include "probe.hpp"

class Sender {
 public:
  virtual void send(const Probe& probe, int n_packets) = 0;
  virtual ~Sender() {}
};
