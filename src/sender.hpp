#pragma once

#include "probe.hpp"

class Sender {
 public:
  virtual void send(Probe& probe, int n_packets) = 0;
  virtual ~Sender(){};
};
