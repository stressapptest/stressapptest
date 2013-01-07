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
#include <algorithm>
#include <string>

#ifdef HAVE_CONFIG_H  // Built using autoconf
#ifdef __ANDROID__
#include "stressapptest_config_android.h"
#else
#include "stressapptest_config.h"
using namespace __gnu_cxx;
#endif
using namespace std;

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

static const bool kOpenSource = true;
#else
static const bool kOpenSource = false;
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
  typedef uint64 cpu_set_t;
  #define CPU_SETSIZE                   (sizeof(cpu_set_t) * 8)
  #define CPU_ISSET(index, cpu_set_ptr) (*(cpu_set_ptr) & 1ull << (index))
  #define CPU_SET(index, cpu_set_ptr)   (*(cpu_set_ptr) |= 1ull << (index))
  #define CPU_ZERO(cpu_set_ptr)         (*(cpu_set_ptr) = 0)
  #define CPU_CLR(index, cpu_set_ptr)   (*(cpu_set_ptr) &= ~(1ull << (index)))
#endif

static inline bool cpuset_isequal(const cpu_set_t *c1, const cpu_set_t *c2) {
  for (int i = 0; i < CPU_SETSIZE; ++i)
    if ((CPU_ISSET(i, c1) != 0) != (CPU_ISSET(i, c2) != 0))
      return false;
  return true;
}

static inline bool cpuset_issubset(const cpu_set_t *c1, const cpu_set_t *c2) {
  for (int i = 0; i < CPU_SETSIZE; ++i)
    if (CPU_ISSET(i, c1) && !CPU_ISSET(i, c2))
      return false;
  return true;
}

static inline int cpuset_count(const cpu_set_t *cpuset) {
  int count = 0;
  for (int i = 0; i < CPU_SETSIZE; ++i)
    if (CPU_ISSET(i, cpuset))
      ++count;
  return count;
}

static inline void cpuset_set_ab(cpu_set_t *cpuset, int a, int b) {
  CPU_ZERO(cpuset);
  for (int i = a; i < b; ++i)
    CPU_SET(i, cpuset);
}

static inline string cpuset_format(const cpu_set_t *cpuset) {
  string format;
  int digit = 0, last_non_zero_size = 1;
  for (int i = 0; i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, cpuset)) {
      digit |= 1 << (i & 3);
    }
    if ((i & 3) == 3) {
      format += char(digit <= 9 ? '0' + digit: 'A' + digit - 10);
      if (digit) {
        last_non_zero_size = format.size();
        digit = 0;
      }
    }
  }
  if (digit) {
    format += char(digit <= 9 ? '0' + digit: 'A' + digit - 10);
    last_non_zero_size = format.size();
  }
  format.erase(last_non_zero_size);
  reverse(format.begin(), format.end());
  return format;
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
#ifdef STRERROR_R_CHAR_P
  return string(strerror_r(error_num, buf, sizeof buf));
#else
  if (strerror_r(error_num, buf, sizeof buf))
    return "unknown failure";
  else
    return string(buf);
#endif
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
