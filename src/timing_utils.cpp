#include "timing_utils.hpp"

#include <cstddef>

using namespace utils;

uint32_t utils::tsdiff(struct timeval *end, struct timeval *begin) {
  // Return with a scale of a tenth of a millisecond.
  uint32_t diff = static_cast<uint32_t>(end->tv_sec - begin->tv_sec) * 10000;
  diff += static_cast<uint32_t>((end->tv_usec - begin->tv_usec) * 0.01);
  return diff;
}

uint32_t utils::tsdiffus(struct timeval *end, struct timeval *begin) {
  uint32_t diff = (end->tv_sec - begin->tv_sec) * 1000000;
  diff += (end->tv_usec - begin->tv_usec);
  return diff;
}

uint32_t utils::elapsed(timeval *now, timeval *start) {
  gettimeofday(now, NULL);
  //    if (config->coarse)
  return tsdiff(now, start);
  //    return tsdiffus(now, start);
}