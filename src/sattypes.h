// Copyright 2006 Google Inc. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef STRESSAPPTEST_SATTYPES_H_
#define STRESSAPPTEST_SATTYPES_H_

#include <arpa/inet.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
#include <string>

#ifdef HAVE_CONFIG_H  // Built using autoconf
#include "stressapptest_config.h"
using namespace std;
using namespace __gnu_cxx;

typedef signed long long   int64;
typedef signed int         int32;
typedef signed short int   int16;
typedef signed char        int8;

typedef unsigned long long uint64;
typedef unsigned int       uint32;
typedef unsigned short     uint16;
typedef unsigned char      uint8;

#define DISALLOW_COPY_AND_ASSIGN(TypeName)        \
  TypeName(const TypeName&);                      \
  void operator=(const TypeName&)

inline const char* Timestamp() {
  return STRESSAPPTEST_TIMESTAMP;
}

inline const char* BuildChangelist() {
  return "open source release";
}

#else
  #include "googlesattypes.h"
#endif
// Workaround to allow 32/64 bit conversion
// without running into strict aliasing problems.
union datacast_t {
  uint64 l64;
  struct {
    uint32 l;
    uint32 h;
  } l32;
};


// File sync'd print to console and log
void logprintf(int priority, const char *format, ...);

// We print to stderr ourselves first in case we're in such a bad state that the
// logger can't work.
#define sat_assert(x) \
{\
  if (!(x)) {\
    fprintf(stderr, "Assertion failed at %s:%d\n", __FILE__, __LINE__);\
    logprintf(0, "Assertion failed at %s:%d\n", __FILE__, __LINE__);\
    exit(1);\
  }\
}

#if !defined(CPU_SETSIZE)
  // Define type and macros for cpu mask operations
  // Note: this code is hacked together to deal with difference
  // function signatures across versions of glibc, ie those that take
  // cpu_set_t versus those that take unsigned long.  -johnhuang
  typedef unsigned long cpu_set_t;
  #define CPU_SETSIZE                   32
  #define CPU_ISSET(index, cpu_set_ptr) (*(cpu_set_ptr) & 1 << (index))
  #define CPU_SET(index, cpu_set_ptr)   (*(cpu_set_ptr) |= 1 << (index))
  #define CPU_ZERO(cpu_set_ptr)         (*(cpu_set_ptr) = 0)
  #define CPU_CLR(index, cpu_set_ptr)   (*(cpu_set_ptr) &= ~(1 << (index)))
#endif

// Make using CPUSET non-super-painful.
static inline uint32 cpuset_to_uint32(cpu_set_t *cpuset) {
  uint32 value = 0;
  for (int index = 0; index < CPU_SETSIZE; index++) {
    if (CPU_ISSET(index, cpuset)) {
      if (index < 32) {
          value |= 1 << index;
      } else {
        logprintf(0, "Process Error: Cpu index (%d) higher than 32\n", index);
        sat_assert(0);
      }
    }
  }
  return value;
}

static inline void cpuset_from_uint32(uint32 mask, cpu_set_t *cpuset) {
  CPU_ZERO(cpuset);
  for (int index = 0; index < 32; index++) {
    if (mask & (1 << index))
      CPU_SET(index, cpuset);
  }
}

static const int32 kUSleepOneSecond = 1000000;

// This is guaranteed not to use signals.
inline bool sat_usleep(int32 microseconds) {
  timespec req;
  req.tv_sec = microseconds / 1000000;
  // Convert microseconds argument to nano seconds.
  req.tv_nsec = (microseconds % 1000000) * 1000;
  return nanosleep(&req, NULL) == 0;
}

// This is guaranteed not to use signals.
inline bool sat_sleep(time_t seconds) {
  timespec req;
  req.tv_sec = seconds;
  req.tv_nsec = 0;
  return nanosleep(&req, NULL) == 0;
}

// Get an error code description for use in error messages.
//
// Args:
//   error_num: an errno error code
inline string ErrorString(int error_num) {
  char buf[256];
  return string(strerror_r(error_num, buf, sizeof buf));
}

// Define handy constants here
static const int kTicksPerSec = 100;
static const int kMegabyte = (1024LL*1024LL);
static const int kSatDiskPageMax = 32;
static const int kSatDiskPage = 8;
static const int kSatPageSize = (1024LL*1024LL);
static const int kCacheLineSize = 64;
static const uint16_t kNetworkPort = 19996;

#endif  // STRESSAPPTEST_SATTYPES_H_
