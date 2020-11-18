#pragma once

#include <sys/time.h>

#include <cstdint>

namespace utils {

uint32_t tsdiff(struct timeval *end, struct timeval *begin);

uint32_t tsdiffus(struct timeval *end, struct timeval *begin);

uint32_t elapsed(timeval *now, timeval *start);

}  // namespace utils
