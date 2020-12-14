#pragma once

#include "probe.hpp"

class Sender {
 public:
  virtual double current_rate() const = 0;
  virtual void send(const Probe& probe, const int n_packets) = 0;
  virtual ~Sender() {}
};
