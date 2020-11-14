#pragma once

#include <cstdint>
#include <sys/time.h>

namespace utils {
    typedef uint64_t ticks;


    /**
     * Routine to control the probing rate
     * @return
     */
    static inline ticks getticks() {
#ifdef __ARM_ARCH
        /*
     Not supported
     See https://stackoverflow.com/questions/40454157/is-there-an-equivalent-instruction-to-rdtsc-in-arm
  */
  return(0);
#else
        uint32_t a, d;
        // asm("cpuid"); // serialization

        asm volatile("rdtsc" : "=a" (a), "=d" (d));
        return (((ticks) a) | (((ticks) d) << 32));
#endif
    }

    uint32_t tsdiff(struct timeval *end, struct timeval *begin);

    uint32_t tsdiffus(struct timeval *end, struct timeval *begin);

    uint32_t elapsed(timeval * now, timeval *start);

}