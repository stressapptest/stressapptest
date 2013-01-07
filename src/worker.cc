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

// worker.cc : individual tasks that can be run in combination to
// stress the system

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/select.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/times.h>

// These are necessary, but on by default
// #define __USE_GNU
// #define __USE_LARGEFILE64
#include <fcntl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/unistd.h>  // for gettid

// For size of block device
#include <sys/ioctl.h>
#include <linux/fs.h>
// For asynchronous I/O
#ifdef HAVE_LIBAIO_H
#include <libaio.h>
#endif

#include <sys/syscall.h>

#include <set>
#include <string>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "error_diag.h"  // NOLINT
#include "os.h"          // NOLINT
#include "pattern.h"     // NOLINT
#include "queue.h"       // NOLINT
#include "sat.h"         // NOLINT
#include "sattypes.h"    // NOLINT
#include "worker.h"      // NOLINT

// Syscalls
// Why ubuntu, do you hate gettid so bad?
#if !defined(__NR_gettid)
  #define __NR_gettid             224
#endif

#define gettid() syscall(__NR_gettid)
#if !defined(CPU_SETSIZE)
_syscall3(int, sched_getaffinity, pid_t, pid,
          unsigned int, len, cpu_set_t*, mask)
_syscall3(int, sched_setaffinity, pid_t, pid,
          unsigned int, len, cpu_set_t*, mask)
#endif

namespace {
  // Get HW core ID from cpuid instruction.
  inline int apicid(void) {
    int cpu;
#if defined(STRESSAPPTEST_CPU_X86_64) || defined(STRESSAPPTEST_CPU_I686)
    __asm __volatile("cpuid" : "=b" (cpu) : "a" (1) : "cx", "dx");
#elif defined(STRESSAPPTEST_CPU_ARMV7A)
  #warning "Unsupported CPU type ARMV7A: unable to determine core ID."
    cpu = 0;
#else
  #warning "Unsupported CPU type: unable to determine core ID."
    cpu = 0;
#endif
    return (cpu >> 24);
  }

  // Work around the sad fact that there are two (gnu, xsi) incompatible
  // versions of strerror_r floating around google. Awesome.
  bool sat_strerror(int err, char *buf, int len) {
    buf[0] = 0;
    char *errmsg = reinterpret_cast<char*>(strerror_r(err, buf, len));
    int retval = reinterpret_cast<int64>(errmsg);
    if (retval == 0)
      return true;
    if (retval == -1)
      return false;
    if (errmsg != buf) {
      strncpy(buf, errmsg, len);
      buf[len - 1] = 0;
    }
    return true;
  }


  inline uint64 addr_to_tag(void *address) {
    return reinterpret_cast<uint64>(address);
  }
}

#if !defined(O_DIRECT)
// Sometimes this isn't available.
// Disregard if it's not defined.
  #define O_DIRECT            0
#endif

// A struct to hold captured errors, for later reporting.
struct ErrorRecord {
  uint64 actual;  // This is the actual value read.
  uint64 reread;  // This is the actual value, reread.
  uint64 expected;  // This is what it should have been.
  uint64 *vaddr;  // This is where it was (or wasn't).
  char *vbyteaddr;  // This is byte specific where the data was (or wasn't).
  uint64 paddr;  // This is the bus address, if available.
  uint64 *tagvaddr;  // This holds the tag value if this data was tagged.
  uint64 tagpaddr;  // This holds the physical address corresponding to the tag.
};

// This is a helper function to create new threads with pthreads.
static void *ThreadSpawnerGeneric(void *ptr) {
  WorkerThread *worker = static_cast<WorkerThread*>(ptr);
  worker->StartRoutine();
  return NULL;
}

void WorkerStatus::Initialize() {
  sat_assert(0 == pthread_mutex_init(&num_workers_mutex_, NULL));
  sat_assert(0 == pthread_rwlock_init(&status_rwlock_, NULL));
#ifdef _POSIX_BARRIERS
  sat_assert(0 == pthread_barrier_init(&pause_barrier_, NULL,
                                       num_workers_ + 1));
#endif
}

void WorkerStatus::Destroy() {
  sat_assert(0 == pthread_mutex_destroy(&num_workers_mutex_));
  sat_assert(0 == pthread_rwlock_destroy(&status_rwlock_));
#ifdef _POSIX_BARRIERS
  sat_assert(0 == pthread_barrier_destroy(&pause_barrier_));
#endif
}

void WorkerStatus::PauseWorkers() {
  if (SetStatus(PAUSE) != PAUSE)
    WaitOnPauseBarrier();
}

void WorkerStatus::ResumeWorkers() {
  if (SetStatus(RUN) == PAUSE)
    WaitOnPauseBarrier();
}

void WorkerStatus::StopWorkers() {
  if (SetStatus(STOP) == PAUSE)
    WaitOnPauseBarrier();
}

bool WorkerStatus::ContinueRunning() {
  // This loop is an optimization.  We use it to immediately re-check the status
  // after resuming from a pause, instead of returning and waiting for the next
  // call to this function.
  for (;;) {
    switch (GetStatus()) {
      case RUN:
        return true;
      case PAUSE:
        // Wait for the other workers to call this function so that
        // PauseWorkers() can return.
        WaitOnPauseBarrier();
        // Wait for ResumeWorkers() to be called.
        WaitOnPauseBarrier();
        break;
      case STOP:
        return false;
    }
  }
}

bool WorkerStatus::ContinueRunningNoPause() {
  return (GetStatus() != STOP);
}

void WorkerStatus::RemoveSelf() {
  // Acquire a read lock on status_rwlock_ while (status_ != PAUSE).
  for (;;) {
    AcquireStatusReadLock();
    if (status_ != PAUSE)
      break;
    // We need to obey PauseWorkers() just like ContinueRunning() would, so that
    // the other threads won't wait on pause_barrier_ forever.
    ReleaseStatusLock();
    // Wait for the other workers to call this function so that PauseWorkers()
    // can return.
    WaitOnPauseBarrier();
    // Wait for ResumeWorkers() to be called.
    WaitOnPauseBarrier();
  }

  // This lock would be unnecessary if we held a write lock instead of a read
  // lock on status_rwlock_, but that would also force all threads calling
  // ContinueRunning() to wait on this one.  Using a separate lock avoids that.
  AcquireNumWorkersLock();
  // Decrement num_workers_ and reinitialize pause_barrier_, which we know isn't
  // in use because (status != PAUSE).
#ifdef _POSIX_BARRIERS
  sat_assert(0 == pthread_barrier_destroy(&pause_barrier_));
  sat_assert(0 == pthread_barrier_init(&pause_barrier_, NULL, num_workers_));
#endif
  --num_workers_;
  ReleaseNumWorkersLock();

  // Release status_rwlock_.
  ReleaseStatusLock();
}


// Parent thread class.
WorkerThread::WorkerThread() {
  status_ = false;
  pages_copied_ = 0;
  errorcount_ = 0;
  runduration_usec_ = 1;
  priority_ = Normal;
  worker_status_ = NULL;
  thread_spawner_ = &ThreadSpawnerGeneric;
  tag_mode_ = false;
}

WorkerThread::~WorkerThread() {}

// Constructors. Just init some default values.
FillThread::FillThread() {
  num_pages_to_fill_ = 0;
}

// Initialize file name to empty.
FileThread::FileThread() {
  filename_ = "";
  devicename_ = "";
  pass_ = 0;
  page_io_ = true;
  crc_page_ = -1;
  local_page_ = NULL;
}

// If file thread used bounce buffer in memory, account for the extra
// copy for memory bandwidth calculation.
float FileThread::GetMemoryCopiedData() {
  if (!os_->normal_mem())
    return GetCopiedData();
  else
    return 0;
}

// Initialize target hostname to be invalid.
NetworkThread::NetworkThread() {
  snprintf(ipaddr_, sizeof(ipaddr_), "Unknown");
  sock_ = 0;
}

// Initialize?
NetworkSlaveThread::NetworkSlaveThread() {
}

// Initialize?
NetworkListenThread::NetworkListenThread() {
}

// Init member variables.
void WorkerThread::InitThread(int thread_num_init,
                              class Sat *sat_init,
                              class OsLayer *os_init,
                              class PatternList *patternlist_init,
                              WorkerStatus *worker_status) {
  sat_assert(worker_status);
  worker_status->AddWorkers(1);

  thread_num_ = thread_num_init;
  sat_ = sat_init;
  os_ = os_init;
  patternlist_ = patternlist_init;
  worker_status_ = worker_status;

  AvailableCpus(&cpu_mask_);
  tag_ = 0xffffffff;

  tag_mode_ = sat_->tag_mode();
}


// Use pthreads to prioritize a system thread.
bool WorkerThread::InitPriority() {
  // This doesn't affect performance that much, and may not be too safe.

  bool ret = BindToCpus(&cpu_mask_);
  if (!ret)
    logprintf(11, "Log: Bind to %s failed.\n",
              cpuset_format(&cpu_mask_).c_str());

  logprintf(11, "Log: Thread %d running on apic ID %d mask %s (%s).\n",
            thread_num_, apicid(),
            CurrentCpusFormat().c_str(),
            cpuset_format(&cpu_mask_).c_str());
#if 0
  if (priority_ == High) {
    sched_param param;
    param.sched_priority = 1;
    // Set the priority; others are unchanged.
    logprintf(0, "Log: Changing priority to SCHED_FIFO %d\n",
              param.sched_priority);
    if (sched_setscheduler(0, SCHED_FIFO, &param)) {
      char buf[256];
      sat_strerror(errno, buf, sizeof(buf));
      logprintf(0, "Process Error: sched_setscheduler "
                   "failed - error %d %s\n",
                errno, buf);
    }
  }
#endif
  return true;
}

// Use pthreads to create a system thread.
int WorkerThread::SpawnThread() {
  // Create the new thread.
  int result = pthread_create(&thread_, NULL, thread_spawner_, this);
  if (result) {
    char buf[256];
    sat_strerror(result, buf, sizeof(buf));
    logprintf(0, "Process Error: pthread_create "
                  "failed - error %d %s\n", result,
              buf);
    status_ = false;
    return false;
  }

  // 0 is pthreads success.
  return true;
}

// Kill the worker thread with SIGINT.
bool WorkerThread::KillThread() {
  return (pthread_kill(thread_, SIGINT) == 0);
}

// Block until thread has exited.
bool WorkerThread::JoinThread() {
  int result = pthread_join(thread_, NULL);

  if (result) {
    logprintf(0, "Process Error: pthread_join failed - error %d\n", result);
    status_ = false;
  }

  // 0 is pthreads success.
  return (!result);
}


void WorkerThread::StartRoutine() {
  InitPriority();
  StartThreadTimer();
  Work();
  StopThreadTimer();
  worker_status_->RemoveSelf();
}


// Thread work loop. Execute until marked finished.
bool WorkerThread::Work() {
  do {
    logprintf(9, "Log: ...\n");
    // Sleep for 1 second.
    sat_sleep(1);
  } while (IsReadyToRun());

  return false;
}


// Returns CPU mask of CPUs available to this process,
// Conceptually, each bit represents a logical CPU, ie:
//   mask = 3  (11b):   cpu0, 1
//   mask = 13 (1101b): cpu0, 2, 3
bool WorkerThread::AvailableCpus(cpu_set_t *cpuset) {
  CPU_ZERO(cpuset);
#ifdef HAVE_SCHED_GETAFFINITY
  return sched_getaffinity(getppid(), sizeof(*cpuset), cpuset) == 0;
#else
  return 0;
#endif
}


// Returns CPU mask of CPUs this thread is bound to,
// Conceptually, each bit represents a logical CPU, ie:
//   mask = 3  (11b):   cpu0, 1
//   mask = 13 (1101b): cpu0, 2, 3
bool WorkerThread::CurrentCpus(cpu_set_t *cpuset) {
  CPU_ZERO(cpuset);
#ifdef HAVE_SCHED_GETAFFINITY
  return sched_getaffinity(0, sizeof(*cpuset), cpuset) == 0;
#else
  return 0;
#endif
}


// Bind worker thread to specified CPU(s)
//   Args:
//     thread_mask: cpu_set_t representing CPUs, ie
//                  mask = 1  (01b):   cpu0
//                  mask = 3  (11b):   cpu0, 1
//                  mask = 13 (1101b): cpu0, 2, 3
//
//   Returns true on success, false otherwise.
bool WorkerThread::BindToCpus(const cpu_set_t *thread_mask) {
  cpu_set_t process_mask;
  AvailableCpus(&process_mask);
  if (cpuset_isequal(thread_mask, &process_mask))
    return true;

  logprintf(11, "Log: available CPU mask - %s\n",
            cpuset_format(&process_mask).c_str());
  if (!cpuset_issubset(thread_mask, &process_mask)) {
    // Invalid cpu_mask, ie cpu not allocated to this process or doesn't exist.
    logprintf(0, "Log: requested CPUs %s not a subset of available %s\n",
              cpuset_format(thread_mask).c_str(),
              cpuset_format(&process_mask).c_str());
    return false;
  }
#ifdef HAVE_SCHED_GETAFFINITY
  return (sched_setaffinity(gettid(), sizeof(*thread_mask), thread_mask) == 0);
#else
  return 0;
#endif
}


// A worker thread can yield itself to give up CPU until it's scheduled again.
//   Returns true on success, false on error.
bool WorkerThread::YieldSelf() {
  return (sched_yield() == 0);
}


// Fill this page with its pattern.
bool WorkerThread::FillPage(struct page_entry *pe) {
  // Error check arguments.
  if (pe == 0) {
    logprintf(0, "Process Error: Fill Page entry null\n");
    return 0;
  }

  // Mask is the bitmask of indexes used by the pattern.
  // It is the pattern size -1. Size is always a power of 2.
  uint64 *memwords = static_cast<uint64*>(pe->addr);
  int length = sat_->page_length();

  if (tag_mode_) {
    // Select tag or data as appropriate.
    for (int i = 0; i < length / wordsize_; i++) {
      datacast_t data;

      if ((i & 0x7) == 0) {
        data.l64 = addr_to_tag(&memwords[i]);
      } else {
        data.l32.l = pe->pattern->pattern(i << 1);
        data.l32.h = pe->pattern->pattern((i << 1) + 1);
      }
      memwords[i] = data.l64;
    }
  } else {
    // Just fill in untagged data directly.
    for (int i = 0; i < length / wordsize_; i++) {
      datacast_t data;

      data.l32.l = pe->pattern->pattern(i << 1);
      data.l32.h = pe->pattern->pattern((i << 1) + 1);
      memwords[i] = data.l64;
    }
  }

  return 1;
}


// Tell the thread how many pages to fill.
void FillThread::SetFillPages(int64 num_pages_to_fill_init) {
  num_pages_to_fill_ = num_pages_to_fill_init;
}

// Fill this page with a random pattern.
bool FillThread::FillPageRandom(struct page_entry *pe) {
  // Error check arguments.
  if (pe == 0) {
    logprintf(0, "Process Error: Fill Page entry null\n");
    return 0;
  }
  if ((patternlist_ == 0) || (patternlist_->Size() == 0)) {
    logprintf(0, "Process Error: No data patterns available\n");
    return 0;
  }

  // Choose a random pattern for this block.
  pe->pattern = patternlist_->GetRandomPattern();
  if (pe->pattern == 0) {
    logprintf(0, "Process Error: Null data pattern\n");
    return 0;
  }

  // Actually fill the page.
  return FillPage(pe);
}


// Memory fill work loop. Execute until alloted pages filled.
bool FillThread::Work() {
  bool result = true;

  logprintf(9, "Log: Starting fill thread %d\n", thread_num_);

  // We want to fill num_pages_to_fill pages, and
  // stop when we've filled that many.
  // We also want to capture early break
  struct page_entry pe;
  int64 loops = 0;
  while (IsReadyToRun() && (loops < num_pages_to_fill_)) {
    result = result && sat_->GetEmpty(&pe);
    if (!result) {
      logprintf(0, "Process Error: fill_thread failed to pop pages, "
                "bailing\n");
      break;
    }

    // Fill the page with pattern
    result = result && FillPageRandom(&pe);
    if (!result) break;

    // Put the page back on the queue.
    result = result && sat_->PutValid(&pe);
    if (!result) {
      logprintf(0, "Process Error: fill_thread failed to push pages, "
                "bailing\n");
      break;
    }
    loops++;
  }

  // Fill in thread status.
  pages_copied_ = loops;
  status_ = result;
  logprintf(9, "Log: Completed %d: Fill thread. Status %d, %d pages filled\n",
            thread_num_, status_, pages_copied_);
  return result;
}


// Print error information about a data miscompare.
void WorkerThread::ProcessError(struct ErrorRecord *error,
                                int priority,
                                const char *message) {
  char dimm_string[256] = "";

  int apic_id = apicid();

  // Determine if this is a write or read error.
  os_->Flush(error->vaddr);
  error->reread = *(error->vaddr);

  char *good = reinterpret_cast<char*>(&(error->expected));
  char *bad = reinterpret_cast<char*>(&(error->actual));

  sat_assert(error->expected != error->actual);
  unsigned int offset = 0;
  for (offset = 0; offset < (sizeof(error->expected) - 1); offset++) {
    if (good[offset] != bad[offset])
      break;
  }

  error->vbyteaddr = reinterpret_cast<char*>(error->vaddr) + offset;

  // Find physical address if possible.
  error->paddr = os_->VirtualToPhysical(error->vbyteaddr);

  // Pretty print DIMM mapping if available.
  os_->FindDimm(error->paddr, dimm_string, sizeof(dimm_string));

  // Report parseable error.
  if (priority < 5) {
    // Run miscompare error through diagnoser for logging and reporting.
    os_->error_diagnoser_->AddMiscompareError(dimm_string,
                                              reinterpret_cast<uint64>
                                              (error->vaddr), 1);

    logprintf(priority,
              "%s: miscompare on CPU %d(0x%s) at %p(0x%llx:%s): "
              "read:0x%016llx, reread:0x%016llx expected:0x%016llx\n",
              message,
              apic_id,
              CurrentCpusFormat().c_str(),
              error->vaddr,
              error->paddr,
              dimm_string,
              error->actual,
              error->reread,
              error->expected);
  }


  // Overwrite incorrect data with correct data to prevent
  // future miscompares when this data is reused.
  *(error->vaddr) = error->expected;
  os_->Flush(error->vaddr);
}



// Print error information about a data miscompare.
void FileThread::ProcessError(struct ErrorRecord *error,
                              int priority,
                              const char *message) {
  char dimm_string[256] = "";

  // Determine if this is a write or read error.
  os_->Flush(error->vaddr);
  error->reread = *(error->vaddr);

  char *good = reinterpret_cast<char*>(&(error->expected));
  char *bad = reinterpret_cast<char*>(&(error->actual));

  sat_assert(error->expected != error->actual);
  unsigned int offset = 0;
  for (offset = 0; offset < (sizeof(error->expected) - 1); offset++) {
    if (good[offset] != bad[offset])
      break;
  }

  error->vbyteaddr = reinterpret_cast<char*>(error->vaddr) + offset;

  // Find physical address if possible.
  error->paddr = os_->VirtualToPhysical(error->vbyteaddr);

  // Pretty print DIMM mapping if available.
  os_->FindDimm(error->paddr, dimm_string, sizeof(dimm_string));

  // If crc_page_ is valid, ie checking content read back from file,
  // track src/dst memory addresses. Otherwise catagorize as general
  // mememory miscompare for CRC checking everywhere else.
  if (crc_page_ != -1) {
    int miscompare_byteoffset = static_cast<char*>(error->vbyteaddr) -
                                static_cast<char*>(page_recs_[crc_page_].dst);
    os_->error_diagnoser_->AddHDDMiscompareError(devicename_,
                                                 crc_page_,
                                                 miscompare_byteoffset,
                                                 page_recs_[crc_page_].src,
                                                 page_recs_[crc_page_].dst);
  } else {
    os_->error_diagnoser_->AddMiscompareError(dimm_string,
                                              reinterpret_cast<uint64>
                                              (error->vaddr), 1);
  }

  logprintf(priority,
            "%s: miscompare on %s at %p(0x%llx:%s): read:0x%016llx, "
            "reread:0x%016llx expected:0x%016llx\n",
            message,
            devicename_.c_str(),
            error->vaddr,
            error->paddr,
            dimm_string,
            error->actual,
            error->reread,
            error->expected);

  // Overwrite incorrect data with correct data to prevent
  // future miscompares when this data is reused.
  *(error->vaddr) = error->expected;
  os_->Flush(error->vaddr);
}


// Do a word by word result check of a region.
// Print errors on mismatches.
int WorkerThread::CheckRegion(void *addr,
                              class Pattern *pattern,
                              int64 length,
                              int offset,
                              int64 pattern_offset) {
  uint64 *memblock = static_cast<uint64*>(addr);
  const int kErrorLimit = 128;
  int errors = 0;
  int overflowerrors = 0;  // Count of overflowed errors.
  bool page_error = false;
  string errormessage("Hardware Error");
  struct ErrorRecord
    recorded[kErrorLimit];  // Queued errors for later printing.

  // For each word in the data region.
  for (int i = 0; i < length / wordsize_; i++) {
    uint64 actual = memblock[i];
    uint64 expected;

    // Determine the value that should be there.
    datacast_t data;
    int index = 2 * i + pattern_offset;
    data.l32.l = pattern->pattern(index);
    data.l32.h = pattern->pattern(index + 1);
    expected = data.l64;
    // Check tags if necessary.
    if (tag_mode_ && ((reinterpret_cast<uint64>(&memblock[i]) & 0x3f) == 0)) {
      expected = addr_to_tag(&memblock[i]);
    }


    // If the value is incorrect, save an error record for later printing.
    if (actual != expected) {
      if (errors < kErrorLimit) {
        recorded[errors].actual = actual;
        recorded[errors].expected = expected;
        recorded[errors].vaddr = &memblock[i];
        errors++;
      } else {
        page_error = true;
        // If we have overflowed the error queue, just print the errors now.
        logprintf(10, "Log: Error record overflow, too many miscompares!\n");
        errormessage = "Page Error";
        break;
      }
    }
  }

  // Find if this is a whole block corruption.
  if (page_error && !tag_mode_) {
    int patsize = patternlist_->Size();
    for (int pat = 0; pat < patsize; pat++) {
      class Pattern *altpattern = patternlist_->GetPattern(pat);
      const int kGood = 0;
      const int kBad = 1;
      const int kGoodAgain = 2;
      const int kNoMatch = 3;
      int state = kGood;
      unsigned int badstart = 0;
      unsigned int badend = 0;

      // Don't match against ourself!
      if (pattern == altpattern)
        continue;

      for (int i = 0; i < length / wordsize_; i++) {
        uint64 actual = memblock[i];
        datacast_t expected;
        datacast_t possible;

        // Determine the value that should be there.
        int index = 2 * i + pattern_offset;

        expected.l32.l = pattern->pattern(index);
        expected.l32.h = pattern->pattern(index + 1);

        possible.l32.l = pattern->pattern(index);
        possible.l32.h = pattern->pattern(index + 1);

        if (state == kGood) {
          if (actual == expected.l64) {
            continue;
          } else if (actual == possible.l64) {
            badstart = i;
            badend = i;
            state = kBad;
            continue;
          } else {
            state = kNoMatch;
            break;
          }
        } else if (state == kBad) {
          if (actual == possible.l64) {
            badend = i;
            continue;
          } else if (actual == expected.l64) {
            state = kGoodAgain;
            continue;
          } else {
            state = kNoMatch;
            break;
          }
        } else if (state == kGoodAgain) {
          if (actual == expected.l64) {
            continue;
          } else {
            state = kNoMatch;
            break;
          }
        }
      }

      if ((state == kGoodAgain) || (state == kBad)) {
        unsigned int blockerrors = badend - badstart + 1;
        errormessage = "Block Error";
        ProcessError(&recorded[0], 0, errormessage.c_str());
        logprintf(0, "Block Error: (%p) pattern %s instead of %s, "
                  "%d bytes from offset 0x%x to 0x%x\n",
                  &memblock[badstart],
                  altpattern->name(), pattern->name(),
                  blockerrors * wordsize_,
                  offset + badstart * wordsize_,
                  offset + badend * wordsize_);
        errorcount_ += blockerrors;
        return blockerrors;
      }
    }
  }


  // Process error queue after all errors have been recorded.
  for (int err = 0; err < errors; err++) {
    int priority = 5;
    if (errorcount_ + err < 30)
      priority = 0;  // Bump up the priority for the first few errors.
    ProcessError(&recorded[err], priority, errormessage.c_str());
  }

  if (page_error) {
    // For each word in the data region.
    int error_recount = 0;
    for (int i = 0; i < length / wordsize_; i++) {
      uint64 actual = memblock[i];
      uint64 expected;
      datacast_t data;
      // Determine the value that should be there.
      int index = 2 * i + pattern_offset;

      data.l32.l = pattern->pattern(index);
      data.l32.h = pattern->pattern(index + 1);
      expected = data.l64;

      // Check tags if necessary.
      if (tag_mode_ && ((reinterpret_cast<uint64>(&memblock[i]) & 0x3f) == 0)) {
        expected = addr_to_tag(&memblock[i]);
      }

      // If the value is incorrect, save an error record for later printing.
      if (actual != expected) {
        if (error_recount < kErrorLimit) {
          // We already reported these.
          error_recount++;
        } else {
          // If we have overflowed the error queue, print the errors now.
          struct ErrorRecord er;
          er.actual = actual;
          er.expected = expected;
          er.vaddr = &memblock[i];

          // Do the error printout. This will take a long time and
          // likely change the machine state.
          ProcessError(&er, 12, errormessage.c_str());
          overflowerrors++;
        }
      }
    }
  }

  // Keep track of observed errors.
  errorcount_ += errors + overflowerrors;
  return errors + overflowerrors;
}

float WorkerThread::GetCopiedData() {
  return pages_copied_ * sat_->page_length() / kMegabyte;
}

// Calculate the CRC of a region.
// Result check if the CRC mismatches.
int WorkerThread::CrcCheckPage(struct page_entry *srcpe) {
  const int blocksize = 4096;
  const int blockwords = blocksize / wordsize_;
  int errors = 0;

  const AdlerChecksum *expectedcrc = srcpe->pattern->crc();
  uint64 *memblock = static_cast<uint64*>(srcpe->addr);
  int blocks = sat_->page_length() / blocksize;
  for (int currentblock = 0; currentblock < blocks; currentblock++) {
    uint64 *memslice = memblock + currentblock * blockwords;

    AdlerChecksum crc;
    if (tag_mode_) {
      AdlerAddrCrcC(memslice, blocksize, &crc, srcpe);
    } else {
      CalculateAdlerChecksum(memslice, blocksize, &crc);
    }

    // If the CRC does not match, we'd better look closer.
    if (!crc.Equals(*expectedcrc)) {
      logprintf(11, "Log: CrcCheckPage Falling through to slow compare, "
                "CRC mismatch %s != %s\n",
                crc.ToHexString().c_str(),
                expectedcrc->ToHexString().c_str());
      int errorcount = CheckRegion(memslice,
                                   srcpe->pattern,
                                   blocksize,
                                   currentblock * blocksize, 0);
      if (errorcount == 0) {
        logprintf(0, "Log: CrcCheckPage CRC mismatch %s != %s, "
                     "but no miscompares found.\n",
                  crc.ToHexString().c_str(),
                  expectedcrc->ToHexString().c_str());
      }
      errors += errorcount;
    }
  }

  // For odd length transfers, we should never hit this.
  int leftovers = sat_->page_length() % blocksize;
  if (leftovers) {
    uint64 *memslice = memblock + blocks * blockwords;
    errors += CheckRegion(memslice,
                          srcpe->pattern,
                          leftovers,
                          blocks * blocksize, 0);
  }
  return errors;
}


// Print error information about a data miscompare.
void WorkerThread::ProcessTagError(struct ErrorRecord *error,
                                   int priority,
                                   const char *message) {
  char dimm_string[256] = "";
  char tag_dimm_string[256] = "";
  bool read_error = false;

  int apic_id = apicid();

  // Determine if this is a write or read error.
  os_->Flush(error->vaddr);
  error->reread = *(error->vaddr);

  // Distinguish read and write errors.
  if (error->actual != error->reread) {
    read_error = true;
  }

  sat_assert(error->expected != error->actual);

  error->vbyteaddr = reinterpret_cast<char*>(error->vaddr);

  // Find physical address if possible.
  error->paddr = os_->VirtualToPhysical(error->vbyteaddr);
  error->tagpaddr = os_->VirtualToPhysical(error->tagvaddr);

  // Pretty print DIMM mapping if available.
  os_->FindDimm(error->paddr, dimm_string, sizeof(dimm_string));
  // Pretty print DIMM mapping if available.
  os_->FindDimm(error->tagpaddr, tag_dimm_string, sizeof(tag_dimm_string));

  // Report parseable error.
  if (priority < 5) {
    logprintf(priority,
              "%s: Tag from %p(0x%llx:%s) (%s) "
              "miscompare on CPU %d(0x%s) at %p(0x%llx:%s): "
              "read:0x%016llx, reread:0x%016llx expected:0x%016llx\n",
              message,
              error->tagvaddr, error->tagpaddr,
              tag_dimm_string,
              read_error ? "read error" : "write error",
              apic_id,
              CurrentCpusFormat().c_str(),
              error->vaddr,
              error->paddr,
              dimm_string,
              error->actual,
              error->reread,
              error->expected);
  }

  errorcount_ += 1;

  // Overwrite incorrect data with correct data to prevent
  // future miscompares when this data is reused.
  *(error->vaddr) = error->expected;
  os_->Flush(error->vaddr);
}


// Print out and log a tag error.
bool WorkerThread::ReportTagError(
    uint64 *mem64,
    uint64 actual,
    uint64 tag) {
  struct ErrorRecord er;
  er.actual = actual;

  er.expected = tag;
  er.vaddr = mem64;

  // Generate vaddr from tag.
  er.tagvaddr = reinterpret_cast<uint64*>(actual);

  ProcessTagError(&er, 0, "Hardware Error");
  return true;
}

// C implementation of Adler memory copy, with memory tagging.
bool WorkerThread::AdlerAddrMemcpyC(uint64 *dstmem64,
                                    uint64 *srcmem64,
                                    unsigned int size_in_bytes,
                                    AdlerChecksum *checksum,
                                    struct page_entry *pe) {
  // Use this data wrapper to access memory with 64bit read/write.
  datacast_t data;
  datacast_t dstdata;
  unsigned int count = size_in_bytes / sizeof(data);

  if (count > ((1U) << 19)) {
    // Size is too large, must be strictly less than 512 KB.
    return false;
  }

  uint64 a1 = 1;
  uint64 a2 = 1;
  uint64 b1 = 0;
  uint64 b2 = 0;

  class Pattern *pattern = pe->pattern;

  unsigned int i = 0;
  while (i < count) {
    // Process 64 bits at a time.
    if ((i & 0x7) == 0) {
      data.l64 = srcmem64[i];
      dstdata.l64 = dstmem64[i];
      uint64 src_tag = addr_to_tag(&srcmem64[i]);
      uint64 dst_tag = addr_to_tag(&dstmem64[i]);
      // Detect if tags have been corrupted.
      if (data.l64 != src_tag)
        ReportTagError(&srcmem64[i], data.l64, src_tag);
      if (dstdata.l64 != dst_tag)
        ReportTagError(&dstmem64[i], dstdata.l64, dst_tag);

      data.l32.l = pattern->pattern(i << 1);
      data.l32.h = pattern->pattern((i << 1) + 1);
      a1 = a1 + data.l32.l;
      b1 = b1 + a1;
      a1 = a1 + data.l32.h;
      b1 = b1 + a1;

      data.l64  = dst_tag;
      dstmem64[i] = data.l64;

    } else {
      data.l64 = srcmem64[i];
      a1 = a1 + data.l32.l;
      b1 = b1 + a1;
      a1 = a1 + data.l32.h;
      b1 = b1 + a1;
      dstmem64[i] = data.l64;
    }
    i++;

    data.l64 = srcmem64[i];
    a2 = a2 + data.l32.l;
    b2 = b2 + a2;
    a2 = a2 + data.l32.h;
    b2 = b2 + a2;
    dstmem64[i] = data.l64;
    i++;
  }
  checksum->Set(a1, a2, b1, b2);
  return true;
}

// x86_64 SSE2 assembly implementation of Adler memory copy, with address
// tagging added as a second step. This is useful for debugging failures
// that only occur when SSE / nontemporal writes are used.
bool WorkerThread::AdlerAddrMemcpyWarm(uint64 *dstmem64,
                                       uint64 *srcmem64,
                                       unsigned int size_in_bytes,
                                       AdlerChecksum *checksum,
                                       struct page_entry *pe) {
  // Do ASM copy, ignore checksum.
  AdlerChecksum ignored_checksum;
  os_->AdlerMemcpyWarm(dstmem64, srcmem64, size_in_bytes, &ignored_checksum);

  // Force cache flush.
  int length = size_in_bytes / sizeof(*dstmem64);
  for (int i = 0; i < length; i += sizeof(*dstmem64)) {
    os_->FastFlush(dstmem64 + i);
    os_->FastFlush(srcmem64 + i);
  }
  // Check results.
  AdlerAddrCrcC(srcmem64, size_in_bytes, checksum, pe);
  // Patch up address tags.
  TagAddrC(dstmem64, size_in_bytes);
  return true;
}

// Retag pages..
bool WorkerThread::TagAddrC(uint64 *memwords,
                            unsigned int size_in_bytes) {
  // Mask is the bitmask of indexes used by the pattern.
  // It is the pattern size -1. Size is always a power of 2.

  // Select tag or data as appropriate.
  int length = size_in_bytes / wordsize_;
  for (int i = 0; i < length; i += 8) {
    datacast_t data;
    data.l64 = addr_to_tag(&memwords[i]);
    memwords[i] = data.l64;
  }
  return true;
}

// C implementation of Adler memory crc.
bool WorkerThread::AdlerAddrCrcC(uint64 *srcmem64,
                                 unsigned int size_in_bytes,
                                 AdlerChecksum *checksum,
                                 struct page_entry *pe) {
  // Use this data wrapper to access memory with 64bit read/write.
  datacast_t data;
  unsigned int count = size_in_bytes / sizeof(data);

  if (count > ((1U) << 19)) {
    // Size is too large, must be strictly less than 512 KB.
    return false;
  }

  uint64 a1 = 1;
  uint64 a2 = 1;
  uint64 b1 = 0;
  uint64 b2 = 0;

  class Pattern *pattern = pe->pattern;

  unsigned int i = 0;
  while (i < count) {
    // Process 64 bits at a time.
    if ((i & 0x7) == 0) {
      data.l64 = srcmem64[i];
      uint64 src_tag = addr_to_tag(&srcmem64[i]);
      // Check that tags match expected.
      if (data.l64 != src_tag)
        ReportTagError(&srcmem64[i], data.l64, src_tag);

      data.l32.l = pattern->pattern(i << 1);
      data.l32.h = pattern->pattern((i << 1) + 1);
      a1 = a1 + data.l32.l;
      b1 = b1 + a1;
      a1 = a1 + data.l32.h;
      b1 = b1 + a1;
    } else {
      data.l64 = srcmem64[i];
      a1 = a1 + data.l32.l;
      b1 = b1 + a1;
      a1 = a1 + data.l32.h;
      b1 = b1 + a1;
    }
    i++;

    data.l64 = srcmem64[i];
    a2 = a2 + data.l32.l;
    b2 = b2 + a2;
    a2 = a2 + data.l32.h;
    b2 = b2 + a2;
    i++;
  }
  checksum->Set(a1, a2, b1, b2);
  return true;
}

// Copy a block of memory quickly, while keeping a CRC of the data.
// Result check if the CRC mismatches.
int WorkerThread::CrcCopyPage(struct page_entry *dstpe,
                              struct page_entry *srcpe) {
  int errors = 0;
  const int blocksize = 4096;
  const int blockwords = blocksize / wordsize_;
  int blocks = sat_->page_length() / blocksize;

  // Base addresses for memory copy
  uint64 *targetmembase = static_cast<uint64*>(dstpe->addr);
  uint64 *sourcemembase = static_cast<uint64*>(srcpe->addr);
  // Remember the expected CRC
  const AdlerChecksum *expectedcrc = srcpe->pattern->crc();

  for (int currentblock = 0; currentblock < blocks; currentblock++) {
    uint64 *targetmem = targetmembase + currentblock * blockwords;
    uint64 *sourcemem = sourcemembase + currentblock * blockwords;

    AdlerChecksum crc;
    if (tag_mode_) {
      AdlerAddrMemcpyC(targetmem, sourcemem, blocksize, &crc, srcpe);
    } else {
      AdlerMemcpyC(targetmem, sourcemem, blocksize, &crc);
    }

    // Investigate miscompares.
    if (!crc.Equals(*expectedcrc)) {
      logprintf(11, "Log: CrcCopyPage Falling through to slow compare, "
                "CRC mismatch %s != %s\n", crc.ToHexString().c_str(),
                expectedcrc->ToHexString().c_str());
      int errorcount = CheckRegion(sourcemem,
                                   srcpe->pattern,
                                   blocksize,
                                   currentblock * blocksize, 0);
      if (errorcount == 0) {
        logprintf(0, "Log: CrcCopyPage CRC mismatch %s != %s, "
                     "but no miscompares found. Retrying with fresh data.\n",
                  crc.ToHexString().c_str(),
                  expectedcrc->ToHexString().c_str());
        if (!tag_mode_) {
          // Copy the data originally read from this region back again.
          // This data should have any corruption read originally while
          // calculating the CRC.
          memcpy(sourcemem, targetmem, blocksize);
          errorcount = CheckRegion(sourcemem,
                                   srcpe->pattern,
                                   blocksize,
                                   currentblock * blocksize, 0);
          if (errorcount == 0) {
            int apic_id = apicid();
            logprintf(0, "Process Error: CPU %d(0x%s) CrcCopyPage "
                         "CRC mismatch %s != %s, "
                         "but no miscompares found on second pass.\n",
                      apic_id, CurrentCpusFormat().c_str(),
                      crc.ToHexString().c_str(),
                      expectedcrc->ToHexString().c_str());
            struct ErrorRecord er;
            er.actual = sourcemem[0];
            er.expected = 0x0;
            er.vaddr = sourcemem;
            ProcessError(&er, 0, "Hardware Error");
          }
        }
      }
      errors += errorcount;
    }
  }

  // For odd length transfers, we should never hit this.
  int leftovers = sat_->page_length() % blocksize;
  if (leftovers) {
    uint64 *targetmem = targetmembase + blocks * blockwords;
    uint64 *sourcemem = sourcemembase + blocks * blockwords;

    errors += CheckRegion(sourcemem,
                          srcpe->pattern,
                          leftovers,
                          blocks * blocksize, 0);
    int leftoverwords = leftovers / wordsize_;
    for (int i = 0; i < leftoverwords; i++) {
      targetmem[i] = sourcemem[i];
    }
  }

  // Update pattern reference to reflect new contents.
  dstpe->pattern = srcpe->pattern;

  // Clean clean clean the errors away.
  if (errors) {
    // TODO(nsanders): Maybe we should patch rather than fill? Filling may
    // cause bad data to be propogated across the page.
    FillPage(dstpe);
  }
  return errors;
}



// Invert a block of memory quickly, traversing downwards.
int InvertThread::InvertPageDown(struct page_entry *srcpe) {
  const int blocksize = 4096;
  const int blockwords = blocksize / wordsize_;
  int blocks = sat_->page_length() / blocksize;

  // Base addresses for memory copy
  unsigned int *sourcemembase = static_cast<unsigned int *>(srcpe->addr);

  for (int currentblock = blocks-1; currentblock >= 0; currentblock--) {
    unsigned int *sourcemem = sourcemembase + currentblock * blockwords;
    for (int i = blockwords - 32; i >= 0; i -= 32) {
      for (int index = i + 31; index >= i; --index) {
        unsigned int actual = sourcemem[index];
        sourcemem[index] = ~actual;
      }
      OsLayer::FastFlush(&sourcemem[i]);
    }
  }

  return 0;
}

// Invert a block of memory, traversing upwards.
int InvertThread::InvertPageUp(struct page_entry *srcpe) {
  const int blocksize = 4096;
  const int blockwords = blocksize / wordsize_;
  int blocks = sat_->page_length() / blocksize;

  // Base addresses for memory copy
  unsigned int *sourcemembase = static_cast<unsigned int *>(srcpe->addr);

  for (int currentblock = 0; currentblock < blocks; currentblock++) {
    unsigned int *sourcemem = sourcemembase + currentblock * blockwords;
    for (int i = 0; i < blockwords; i += 32) {
      for (int index = i; index <= i + 31; ++index) {
        unsigned int actual = sourcemem[index];
        sourcemem[index] = ~actual;
      }
      OsLayer::FastFlush(&sourcemem[i]);
    }
  }
  return 0;
}

// Copy a block of memory quickly, while keeping a CRC of the data.
// Result check if the CRC mismatches. Warm the CPU while running
int WorkerThread::CrcWarmCopyPage(struct page_entry *dstpe,
                                  struct page_entry *srcpe) {
  int errors = 0;
  const int blocksize = 4096;
  const int blockwords = blocksize / wordsize_;
  int blocks = sat_->page_length() / blocksize;

  // Base addresses for memory copy
  uint64 *targetmembase = static_cast<uint64*>(dstpe->addr);
  uint64 *sourcemembase = static_cast<uint64*>(srcpe->addr);
  // Remember the expected CRC
  const AdlerChecksum *expectedcrc = srcpe->pattern->crc();

  for (int currentblock = 0; currentblock < blocks; currentblock++) {
    uint64 *targetmem = targetmembase + currentblock * blockwords;
    uint64 *sourcemem = sourcemembase + currentblock * blockwords;

    AdlerChecksum crc;
    if (tag_mode_) {
      AdlerAddrMemcpyWarm(targetmem, sourcemem, blocksize, &crc, srcpe);
    } else {
      os_->AdlerMemcpyWarm(targetmem, sourcemem, blocksize, &crc);
    }

    // Investigate miscompares.
    if (!crc.Equals(*expectedcrc)) {
      logprintf(11, "Log: CrcWarmCopyPage Falling through to slow compare, "
                "CRC mismatch %s != %s\n", crc.ToHexString().c_str(),
                expectedcrc->ToHexString().c_str());
      int errorcount = CheckRegion(sourcemem,
                                   srcpe->pattern,
                                   blocksize,
                                   currentblock * blocksize, 0);
      if (errorcount == 0) {
        logprintf(0, "Log: CrcWarmCopyPage CRC mismatch %s != %s, "
                     "but no miscompares found. Retrying with fresh data.\n",
                  crc.ToHexString().c_str(),
                  expectedcrc->ToHexString().c_str());
        if (!tag_mode_) {
          // Copy the data originally read from this region back again.
          // This data should have any corruption read originally while
          // calculating the CRC.
          memcpy(sourcemem, targetmem, blocksize);
          errorcount = CheckRegion(sourcemem,
                                   srcpe->pattern,
                                   blocksize,
                                   currentblock * blocksize, 0);
          if (errorcount == 0) {
            int apic_id = apicid();
            logprintf(0, "Process Error: CPU %d(0x%s) CrciWarmCopyPage "
                         "CRC mismatch %s != %s, "
                         "but no miscompares found on second pass.\n",
                      apic_id, CurrentCpusFormat().c_str(),
                      crc.ToHexString().c_str(),
                      expectedcrc->ToHexString().c_str());
            struct ErrorRecord er;
            er.actual = sourcemem[0];
            er.expected = 0x0;
            er.vaddr = sourcemem;
            ProcessError(&er, 0, "Hardware Error");
          }
        }
      }
      errors += errorcount;
    }
  }

  // For odd length transfers, we should never hit this.
  int leftovers = sat_->page_length() % blocksize;
  if (leftovers) {
    uint64 *targetmem = targetmembase + blocks * blockwords;
    uint64 *sourcemem = sourcemembase + blocks * blockwords;

    errors += CheckRegion(sourcemem,
                          srcpe->pattern,
                          leftovers,
                          blocks * blocksize, 0);
    int leftoverwords = leftovers / wordsize_;
    for (int i = 0; i < leftoverwords; i++) {
      targetmem[i] = sourcemem[i];
    }
  }

  // Update pattern reference to reflect new contents.
  dstpe->pattern = srcpe->pattern;

  // Clean clean clean the errors away.
  if (errors) {
    // TODO(nsanders): Maybe we should patch rather than fill? Filling may
    // cause bad data to be propogated across the page.
    FillPage(dstpe);
  }
  return errors;
}



// Memory check work loop. Execute until done, then exhaust pages.
bool CheckThread::Work() {
  struct page_entry pe;
  bool result = true;
  int64 loops = 0;

  logprintf(9, "Log: Starting Check thread %d\n", thread_num_);

  // We want to check all the pages, and
  // stop when there aren't any left.
  while (true) {
    result = result && sat_->GetValid(&pe);
    if (!result) {
      if (IsReadyToRunNoPause())
        logprintf(0, "Process Error: check_thread failed to pop pages, "
                  "bailing\n");
      else
        result = true;
      break;
    }

    // Do the result check.
    CrcCheckPage(&pe);

    // Push pages back on the valid queue if we are still going,
    // throw them out otherwise.
    if (IsReadyToRunNoPause())
      result = result && sat_->PutValid(&pe);
    else
      result = result && sat_->PutEmpty(&pe);
    if (!result) {
      logprintf(0, "Process Error: check_thread failed to push pages, "
                "bailing\n");
      break;
    }
    loops++;
  }

  pages_copied_ = loops;
  status_ = result;
  logprintf(9, "Log: Completed %d: Check thread. Status %d, %d pages checked\n",
            thread_num_, status_, pages_copied_);
  return result;
}


// Memory copy work loop. Execute until marked done.
bool CopyThread::Work() {
  struct page_entry src;
  struct page_entry dst;
  bool result = true;
  int64 loops = 0;

  logprintf(9, "Log: Starting copy thread %d: cpu %s, mem %x\n",
            thread_num_, cpuset_format(&cpu_mask_).c_str(), tag_);

  while (IsReadyToRun()) {
    // Pop the needed pages.
    result = result && sat_->GetValid(&src, tag_);
    result = result && sat_->GetEmpty(&dst, tag_);
    if (!result) {
      logprintf(0, "Process Error: copy_thread failed to pop pages, "
                "bailing\n");
      break;
    }

    // Force errors for unittests.
    if (sat_->error_injection()) {
      if (loops == 8) {
        char *addr = reinterpret_cast<char*>(src.addr);
        int offset = random() % sat_->page_length();
        addr[offset] = 0xba;
      }
    }

    // We can use memcpy, or CRC check while we copy.
    if (sat_->warm()) {
      CrcWarmCopyPage(&dst, &src);
    } else if (sat_->strict()) {
      CrcCopyPage(&dst, &src);
    } else {
      memcpy(dst.addr, src.addr, sat_->page_length());
      dst.pattern = src.pattern;
    }

    result = result && sat_->PutValid(&dst);
    result = result && sat_->PutEmpty(&src);

    // Copy worker-threads yield themselves at the end of each copy loop,
    // to avoid threads from preempting each other in the middle of the inner
    // copy-loop. Cooperations between Copy worker-threads results in less
    // unnecessary cache thrashing (which happens when context-switching in the
    // middle of the inner copy-loop).
    YieldSelf();

    if (!result) {
      logprintf(0, "Process Error: copy_thread failed to push pages, "
                "bailing\n");
      break;
    }
    loops++;
  }

  pages_copied_ = loops;
  status_ = result;
  logprintf(9, "Log: Completed %d: Copy thread. Status %d, %d pages copied\n",
            thread_num_, status_, pages_copied_);
  return result;
}

// Memory invert work loop. Execute until marked done.
bool InvertThread::Work() {
  struct page_entry src;
  bool result = true;
  int64 loops = 0;

  logprintf(9, "Log: Starting invert thread %d\n", thread_num_);

  while (IsReadyToRun()) {
    // Pop the needed pages.
    result = result && sat_->GetValid(&src);
    if (!result) {
      logprintf(0, "Process Error: invert_thread failed to pop pages, "
                "bailing\n");
      break;
    }

    if (sat_->strict())
      CrcCheckPage(&src);

    // For the same reason CopyThread yields itself (see YieldSelf comment
    // in CopyThread::Work(), InvertThread yields itself after each invert
    // operation to improve cooperation between different worker threads
    // stressing the memory/cache.
    InvertPageUp(&src);
    YieldSelf();
    InvertPageDown(&src);
    YieldSelf();
    InvertPageDown(&src);
    YieldSelf();
    InvertPageUp(&src);
    YieldSelf();

    if (sat_->strict())
      CrcCheckPage(&src);

    result = result && sat_->PutValid(&src);
    if (!result) {
      logprintf(0, "Process Error: invert_thread failed to push pages, "
                "bailing\n");
      break;
    }
    loops++;
  }

  pages_copied_ = loops * 2;
  status_ = result;
  logprintf(9, "Log: Completed %d: Copy thread. Status %d, %d pages copied\n",
            thread_num_, status_, pages_copied_);
  return result;
}


// Set file name to use for File IO.
void FileThread::SetFile(const char *filename_init) {
  filename_ = filename_init;
  devicename_ = os_->FindFileDevice(filename_);
}

// Open the file for access.
bool FileThread::OpenFile(int *pfile) {
  bool no_O_DIRECT = false;
  int flags = O_RDWR | O_CREAT | O_SYNC;
  int fd = open(filename_.c_str(), flags | O_DIRECT, 0644);
  if (O_DIRECT != 0 && fd < 0 && errno == EINVAL) {
    no_O_DIRECT = true;
    fd = open(filename_.c_str(), flags, 0644); // Try without O_DIRECT
  }
  if (fd < 0) {
    logprintf(0, "Process Error: Failed to create file %s!!\n",
              filename_.c_str());
    pages_copied_ = 0;
    return false;
  }
  if (no_O_DIRECT)
    os_->ActivateFlushPageCache(); // Not using O_DIRECT fixed EINVAL
  *pfile = fd;
  return true;
}

// Close the file.
bool FileThread::CloseFile(int fd) {
  close(fd);
  return true;
}

// Check sector tagging.
bool FileThread::SectorTagPage(struct page_entry *src, int block) {
  int page_length = sat_->page_length();
  struct FileThread::SectorTag *tag =
    (struct FileThread::SectorTag *)(src->addr);

  // Tag each sector.
  unsigned char magic = ((0xba + thread_num_) & 0xff);
  for (int sec = 0; sec < page_length / 512; sec++) {
    tag[sec].magic = magic;
    tag[sec].block = block & 0xff;
    tag[sec].sector = sec & 0xff;
    tag[sec].pass = pass_ & 0xff;
  }
  return true;
}

bool FileThread::WritePageToFile(int fd, struct page_entry *src) {
  int page_length = sat_->page_length();
  // Fill the file with our data.
  int64 size = write(fd, src->addr, page_length);

  if (size != page_length) {
    os_->ErrorReport(devicename_.c_str(), "write-error", 1);
    errorcount_++;
    logprintf(0, "Block Error: file_thread failed to write, "
              "bailing\n");
    return false;
  }
  return true;
}

// Write the data to the file.
bool FileThread::WritePages(int fd) {
  int strict = sat_->strict();

  // Start fresh at beginning of file for each batch of pages.
  lseek64(fd, 0, SEEK_SET);
  for (int i = 0; i < sat_->disk_pages(); i++) {
    struct page_entry src;
    if (!GetValidPage(&src))
      return false;
    // Save expected pattern.
    page_recs_[i].pattern = src.pattern;
    page_recs_[i].src = src.addr;

    // Check data correctness.
    if (strict)
      CrcCheckPage(&src);

    SectorTagPage(&src, i);

    bool result = WritePageToFile(fd, &src);

    if (!PutEmptyPage(&src))
      return false;

    if (!result)
      return false;
  }
  return os_->FlushPageCache(); // If O_DIRECT worked, this will be a NOP.
}

// Copy data from file into memory block.
bool FileThread::ReadPageFromFile(int fd, struct page_entry *dst) {
  int page_length = sat_->page_length();

  // Do the actual read.
  int64 size = read(fd, dst->addr, page_length);
  if (size != page_length) {
    os_->ErrorReport(devicename_.c_str(), "read-error", 1);
    logprintf(0, "Block Error: file_thread failed to read, "
              "bailing\n");
    errorcount_++;
    return false;
  }
  return true;
}

// Check sector tagging.
bool FileThread::SectorValidatePage(const struct PageRec &page,
                                    struct page_entry *dst, int block) {
  // Error injection.
  static int calls = 0;
  calls++;

  // Do sector tag compare.
  int firstsector = -1;
  int lastsector = -1;
  bool badsector = false;
  int page_length = sat_->page_length();

  // Cast data block into an array of tagged sectors.
  struct FileThread::SectorTag *tag =
  (struct FileThread::SectorTag *)(dst->addr);

  sat_assert(sizeof(*tag) == 512);

  // Error injection.
  if (sat_->error_injection()) {
    if (calls == 2) {
      for (int badsec = 8; badsec < 17; badsec++)
        tag[badsec].pass = 27;
    }
    if (calls == 18) {
      (static_cast<int32*>(dst->addr))[27] = 0xbadda7a;
    }
  }

  // Check each sector for the correct tag we added earlier,
  // then revert the tag to the to normal data pattern.
  unsigned char magic = ((0xba + thread_num_) & 0xff);
  for (int sec = 0; sec < page_length / 512; sec++) {
    // Check magic tag.
    if ((tag[sec].magic != magic) ||
        (tag[sec].block != (block & 0xff)) ||
        (tag[sec].sector != (sec & 0xff)) ||
        (tag[sec].pass != (pass_ & 0xff))) {
      // Offset calculation for tag location.
      int offset = sec * sizeof(SectorTag);
      if (tag[sec].block != (block & 0xff))
        offset += 1 * sizeof(uint8);
      else if (tag[sec].sector != (sec & 0xff))
        offset += 2 * sizeof(uint8);
      else if (tag[sec].pass != (pass_ & 0xff))
        offset += 3 * sizeof(uint8);

      // Run sector tag error through diagnoser for logging and reporting.
      errorcount_ += 1;
      os_->error_diagnoser_->AddHDDSectorTagError(devicename_, tag[sec].block,
                                                  offset,
                                                  tag[sec].sector,
                                                  page.src, page.dst);

      logprintf(5, "Sector Error: Sector tag @ 0x%x, pass %d/%d. "
                "sec %x/%x, block %d/%d, magic %x/%x, File: %s \n",
                block * page_length + 512 * sec,
                (pass_ & 0xff), (unsigned int)tag[sec].pass,
                sec, (unsigned int)tag[sec].sector,
                block, (unsigned int)tag[sec].block,
                magic, (unsigned int)tag[sec].magic,
                filename_.c_str());

      // Keep track of first and last bad sector.
      if (firstsector == -1)
        firstsector = (block * page_length / 512) + sec;
      lastsector = (block * page_length / 512) + sec;
      badsector = true;
    }
    // Patch tag back to proper pattern.
    unsigned int *addr = (unsigned int *)(&tag[sec]);
    *addr = dst->pattern->pattern(512 * sec / sizeof(*addr));
  }

  // If we found sector errors:
  if (badsector == true) {
    logprintf(5, "Log: file sector miscompare at offset %x-%x. File: %s\n",
              firstsector * 512,
              ((lastsector + 1) * 512) - 1,
              filename_.c_str());

    // Either exit immediately, or patch the data up and continue.
    if (sat_->stop_on_error()) {
      exit(1);
    } else {
      // Patch up bad pages.
      for (int block = (firstsector * 512) / page_length;
          block <= (lastsector * 512) / page_length;
          block++) {
        unsigned int *memblock = static_cast<unsigned int *>(dst->addr);
        int length = page_length / wordsize_;
        for (int i = 0; i < length; i++) {
          memblock[i] = dst->pattern->pattern(i);
        }
      }
    }
  }
  return true;
}

// Get memory for an incoming data transfer..
bool FileThread::PagePrepare() {
  // We can only do direct IO to SAT pages if it is normal mem.
  page_io_ = os_->normal_mem();

  // Init a local buffer if we need it.
  if (!page_io_) {
#ifdef HAVE_POSIX_MEMALIGN
    int result = posix_memalign(&local_page_, 512, sat_->page_length());
#else
    local_page_ = memalign(512, sat_->page_length());
    int result = (local_page_ == 0);
#endif
    if (result) {
      logprintf(0, "Process Error: disk thread posix_memalign "
                   "returned %d (fail)\n",
                result);
      status_ = false;
      return false;
    }
  }
  return true;
}


// Remove memory allocated for data transfer.
bool FileThread::PageTeardown() {
  // Free a local buffer if we need to.
  if (!page_io_) {
    free(local_page_);
  }
  return true;
}



// Get memory for an incoming data transfer..
bool FileThread::GetEmptyPage(struct page_entry *dst) {
  if (page_io_) {
    if (!sat_->GetEmpty(dst))
      return false;
  } else {
    dst->addr = local_page_;
    dst->offset = 0;
    dst->pattern = 0;
  }
  return true;
}

// Get memory for an outgoing data transfer..
bool FileThread::GetValidPage(struct page_entry *src) {
  struct page_entry tmp;
  if (!sat_->GetValid(&tmp))
    return false;
  if (page_io_) {
    *src = tmp;
    return true;
  } else {
    src->addr = local_page_;
    src->offset = 0;
    CrcCopyPage(src, &tmp);
    if (!sat_->PutValid(&tmp))
      return false;
  }
  return true;
}


// Throw out a used empty page.
bool FileThread::PutEmptyPage(struct page_entry *src) {
  if (page_io_) {
    if (!sat_->PutEmpty(src))
      return false;
  }
  return true;
}

// Throw out a used, filled page.
bool FileThread::PutValidPage(struct page_entry *src) {
  if (page_io_) {
    if (!sat_->PutValid(src))
      return false;
  }
  return true;
}

// Copy data from file into memory blocks.
bool FileThread::ReadPages(int fd) {
  int page_length = sat_->page_length();
  int strict = sat_->strict();
  bool result = true;

  // Read our data back out of the file, into it's new location.
  lseek64(fd, 0, SEEK_SET);
  for (int i = 0; i < sat_->disk_pages(); i++) {
    struct page_entry dst;
    if (!GetEmptyPage(&dst))
      return false;
    // Retrieve expected pattern.
    dst.pattern = page_recs_[i].pattern;
    // Update page recordpage record.
    page_recs_[i].dst = dst.addr;

    // Read from the file into destination page.
    if (!ReadPageFromFile(fd, &dst)) {
        PutEmptyPage(&dst);
        return false;
    }

    SectorValidatePage(page_recs_[i], &dst, i);

    // Ensure that the transfer ended up with correct data.
    if (strict) {
      // Record page index currently CRC checked.
      crc_page_ = i;
      int errors = CrcCheckPage(&dst);
      if (errors) {
        logprintf(5, "Log: file miscompare at block %d, "
                  "offset %x-%x. File: %s\n",
                  i, i * page_length, ((i + 1) * page_length) - 1,
                  filename_.c_str());
        result = false;
      }
      crc_page_ = -1;
      errorcount_ += errors;
    }
    if (!PutValidPage(&dst))
      return false;
  }
  return result;
}

// File IO work loop. Execute until marked done.
bool FileThread::Work() {
  bool result = true;
  int64 loops = 0;

  logprintf(9, "Log: Starting file thread %d, file %s, device %s\n",
            thread_num_,
            filename_.c_str(),
            devicename_.c_str());

  if (!PagePrepare()) {
    status_ = false;
    return false;
  }

  // Open the data IO file.
  int fd = 0;
  if (!OpenFile(&fd)) {
    status_ = false;
    return false;
  }

  pass_ = 0;

  // Load patterns into page records.
  page_recs_ = new struct PageRec[sat_->disk_pages()];
  for (int i = 0; i < sat_->disk_pages(); i++) {
    page_recs_[i].pattern = new struct Pattern();
  }

  // Loop until done.
  while (IsReadyToRun()) {
    // Do the file write.
    if (!(result = result && WritePages(fd)))
      break;

    // Do the file read.
    if (!(result = result && ReadPages(fd)))
      break;

    loops++;
    pass_ = loops;
  }

  pages_copied_ = loops * sat_->disk_pages();

  // Clean up.
  CloseFile(fd);
  PageTeardown();

  logprintf(9, "Log: Completed %d: file thread status %d, %d pages copied\n",
            thread_num_, status_, pages_copied_);
  // Failure to read from device indicates hardware,
  // rather than procedural SW error.
  status_ = true;
  return true;
}

bool NetworkThread::IsNetworkStopSet() {
  return !IsReadyToRunNoPause();
}

bool NetworkSlaveThread::IsNetworkStopSet() {
  // This thread has no completion status.
  // It finishes whever there is no more data to be
  // passed back.
  return true;
}

// Set ip name to use for Network IO.
void NetworkThread::SetIP(const char *ipaddr_init) {
  strncpy(ipaddr_, ipaddr_init, 256);
}

// Create a socket.
// Return 0 on error.
bool NetworkThread::CreateSocket(int *psocket) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock == -1) {
    logprintf(0, "Process Error: Cannot open socket\n");
    pages_copied_ = 0;
    status_ = false;
    return false;
  }
  *psocket = sock;
  return true;
}

// Close the socket.
bool NetworkThread::CloseSocket(int sock) {
  close(sock);
  return true;
}

// Initiate the tcp connection.
bool NetworkThread::Connect(int sock) {
  struct sockaddr_in dest_addr;
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(kNetworkPort);
  memset(&(dest_addr.sin_zero), '\0', sizeof(dest_addr.sin_zero));

  // Translate dot notation to u32.
  if (inet_aton(ipaddr_, &dest_addr.sin_addr) == 0) {
    logprintf(0, "Process Error: Cannot resolve %s\n", ipaddr_);
    pages_copied_ = 0;
    status_ = false;
    return false;
  }

  if (-1 == connect(sock, reinterpret_cast<struct sockaddr *>(&dest_addr),
                    sizeof(struct sockaddr))) {
    logprintf(0, "Process Error: Cannot connect %s\n", ipaddr_);
    pages_copied_ = 0;
    status_ = false;
    return false;
  }
  return true;
}

// Initiate the tcp connection.
bool NetworkListenThread::Listen() {
  struct sockaddr_in sa;

  memset(&(sa.sin_zero), '\0', sizeof(sa.sin_zero));

  sa.sin_family = AF_INET;
  sa.sin_addr.s_addr = INADDR_ANY;
  sa.sin_port = htons(kNetworkPort);

  if (-1 == bind(sock_, (struct sockaddr*)&sa, sizeof(struct sockaddr))) {
    char buf[256];
    sat_strerror(errno, buf, sizeof(buf));
    logprintf(0, "Process Error: Cannot bind socket: %s\n", buf);
    pages_copied_ = 0;
    status_ = false;
    return false;
  }
  listen(sock_, 3);
  return true;
}

// Wait for a connection from a network traffic generation thread.
bool NetworkListenThread::Wait() {
    fd_set rfds;
    struct timeval tv;
    int retval;

    // Watch sock_ to see when it has input.
    FD_ZERO(&rfds);
    FD_SET(sock_, &rfds);
    // Wait up to five seconds.
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    retval = select(sock_ + 1, &rfds, NULL, NULL, &tv);

    return (retval > 0);
}

// Wait for a connection from a network traffic generation thread.
bool NetworkListenThread::GetConnection(int *pnewsock) {
  struct sockaddr_in sa;
  socklen_t size = sizeof(struct sockaddr_in);

  int newsock = accept(sock_, reinterpret_cast<struct sockaddr *>(&sa), &size);
  if (newsock < 0)  {
    logprintf(0, "Process Error: Did not receive connection\n");
    pages_copied_ = 0;
    status_ = false;
    return false;
  }
  *pnewsock = newsock;
  return true;
}

// Send a page, return false if a page was not sent.
bool NetworkThread::SendPage(int sock, struct page_entry *src) {
  int page_length = sat_->page_length();
  char *address = static_cast<char*>(src->addr);

  // Send our data over the network.
  int size = page_length;
  while (size) {
    int transferred = send(sock, address + (page_length - size), size, 0);
    if ((transferred == 0) || (transferred == -1)) {
      if (!IsNetworkStopSet()) {
        char buf[256] = "";
        sat_strerror(errno, buf, sizeof(buf));
        logprintf(0, "Process Error: Thread %d, "
                     "Network write failed, bailing. (%s)\n",
                  thread_num_, buf);
        status_ = false;
      }
      return false;
    }
    size = size - transferred;
  }
  return true;
}

// Receive a page. Return false if a page was not received.
bool NetworkThread::ReceivePage(int sock, struct page_entry *dst) {
  int page_length = sat_->page_length();
  char *address = static_cast<char*>(dst->addr);

  // Maybe we will get our data back again, maybe not.
  int size = page_length;
  while (size) {
    int transferred = recv(sock, address + (page_length - size), size, 0);
    if ((transferred == 0) || (transferred == -1)) {
      // Typically network slave thread should exit as network master
      // thread stops sending data.
      if (IsNetworkStopSet()) {
        int err = errno;
        if (transferred == 0 && err == 0) {
          // Two system setups will not sync exactly,
          // allow early exit, but log it.
          logprintf(0, "Log: Net thread did not receive any data, exiting.\n");
        } else {
          char buf[256] = "";
          sat_strerror(err, buf, sizeof(buf));
          // Print why we failed.
          logprintf(0, "Process Error: Thread %d, "
                       "Network read failed, bailing (%s).\n",
                    thread_num_, buf);
          status_ = false;
          // Print arguments and results.
          logprintf(0, "Log: recv(%d, address %x, size %x, 0) == %x, err %d\n",
                    sock, address + (page_length - size),
                    size, transferred, err);
          if ((transferred == 0) &&
              (page_length - size < 512) &&
              (page_length - size > 0)) {
            // Print null terminated data received, to see who's been
            // sending us supicious unwanted data.
            address[page_length - size] = 0;
            logprintf(0, "Log: received  %d bytes: '%s'\n",
                      page_length - size, address);
          }
        }
      }
      return false;
    }
    size = size - transferred;
  }
  return true;
}

// Network IO work loop. Execute until marked done.
// Return true if the thread ran as expected.
bool NetworkThread::Work() {
  logprintf(9, "Log: Starting network thread %d, ip %s\n",
            thread_num_,
            ipaddr_);

  // Make a socket.
  int sock = 0;
  if (!CreateSocket(&sock))
    return false;

  // Network IO loop requires network slave thread to have already initialized.
  // We will sleep here for awhile to ensure that the slave thread will be
  // listening by the time we connect.
  // Sleep for 15 seconds.
  sat_sleep(15);
  logprintf(9, "Log: Starting execution of network thread %d, ip %s\n",
            thread_num_,
            ipaddr_);


  // Connect to a slave thread.
  if (!Connect(sock))
    return false;

  // Loop until done.
  bool result = true;
  int strict = sat_->strict();
  int64 loops = 0;
  while (IsReadyToRun()) {
    struct page_entry src;
    struct page_entry dst;
    result = result && sat_->GetValid(&src);
    result = result && sat_->GetEmpty(&dst);
    if (!result) {
      logprintf(0, "Process Error: net_thread failed to pop pages, "
                "bailing\n");
      break;
    }

    // Check data correctness.
    if (strict)
      CrcCheckPage(&src);

    // Do the network write.
    if (!(result = result && SendPage(sock, &src)))
      break;

    // Update pattern reference to reflect new contents.
    dst.pattern = src.pattern;

    // Do the network read.
    if (!(result = result && ReceivePage(sock, &dst)))
      break;

    // Ensure that the transfer ended up with correct data.
    if (strict)
      CrcCheckPage(&dst);

    // Return all of our pages to the queue.
    result = result && sat_->PutValid(&dst);
    result = result && sat_->PutEmpty(&src);
    if (!result) {
      logprintf(0, "Process Error: net_thread failed to push pages, "
                "bailing\n");
      break;
    }
    loops++;
  }

  pages_copied_ = loops;
  status_ = result;

  // Clean up.
  CloseSocket(sock);

  logprintf(9, "Log: Completed %d: network thread status %d, "
               "%d pages copied\n",
            thread_num_, status_, pages_copied_);
  return result;
}

// Spawn slave threads for incoming connections.
bool NetworkListenThread::SpawnSlave(int newsock, int threadid) {
  logprintf(12, "Log: Listen thread spawning slave\n");

  // Spawn slave thread, to reflect network traffic back to sender.
  ChildWorker *child_worker = new ChildWorker;
  child_worker->thread.SetSock(newsock);
  child_worker->thread.InitThread(threadid, sat_, os_, patternlist_,
                                  &child_worker->status);
  child_worker->status.Initialize();
  child_worker->thread.SpawnThread();
  child_workers_.push_back(child_worker);

  return true;
}

// Reap slave threads.
bool NetworkListenThread::ReapSlaves() {
  bool result = true;
  // Gather status and reap threads.
  logprintf(12, "Log: Joining all outstanding threads\n");

  for (size_t i = 0; i < child_workers_.size(); i++) {
    NetworkSlaveThread& child_thread = child_workers_[i]->thread;
    logprintf(12, "Log: Joining slave thread %d\n", i);
    child_thread.JoinThread();
    if (child_thread.GetStatus() != 1) {
      logprintf(0, "Process Error: Slave Thread %d failed with status %d\n", i,
                child_thread.GetStatus());
      result = false;
    }
    errorcount_ += child_thread.GetErrorCount();
    logprintf(9, "Log: Slave Thread %d found %lld miscompares\n", i,
              child_thread.GetErrorCount());
    pages_copied_ += child_thread.GetPageCount();
  }

  return result;
}

// Network listener IO work loop. Execute until marked done.
// Return false on fatal software error.
bool NetworkListenThread::Work() {
  logprintf(9, "Log: Starting network listen thread %d\n",
            thread_num_);

  // Make a socket.
  sock_ = 0;
  if (!CreateSocket(&sock_)) {
    status_ = false;
    return false;
  }
  logprintf(9, "Log: Listen thread created sock\n");

  // Allows incoming connections to be queued up by socket library.
  int newsock = 0;
  Listen();
  logprintf(12, "Log: Listen thread waiting for incoming connections\n");

  // Wait on incoming connections, and spawn worker threads for them.
  int threadcount = 0;
  while (IsReadyToRun()) {
    // Poll for connections that we can accept().
    if (Wait()) {
      // Accept those connections.
      logprintf(12, "Log: Listen thread found incoming connection\n");
      if (GetConnection(&newsock)) {
        SpawnSlave(newsock, threadcount);
        threadcount++;
      }
    }
  }

  // Gather status and join spawned threads.
  ReapSlaves();

  // Delete the child workers.
  for (ChildVector::iterator it = child_workers_.begin();
       it != child_workers_.end(); ++it) {
    (*it)->status.Destroy();
    delete *it;
  }
  child_workers_.clear();

  CloseSocket(sock_);

  status_ = true;
  logprintf(9,
            "Log: Completed %d: network listen thread status %d, "
            "%d pages copied\n",
            thread_num_, status_, pages_copied_);
  return true;
}

// Set network reflector socket struct.
void NetworkSlaveThread::SetSock(int sock) {
  sock_ = sock;
}

// Network reflector IO work loop. Execute until marked done.
// Return false on fatal software error.
bool NetworkSlaveThread::Work() {
  logprintf(9, "Log: Starting network slave thread %d\n",
            thread_num_);

  // Verify that we have a socket.
  int sock = sock_;
  if (!sock) {
    status_ = false;
    return false;
  }

  // Loop until done.
  int64 loops = 0;
  // Init a local buffer for storing data.
  void *local_page = NULL;
#ifdef HAVE_POSIX_MEMALIGN
  int result = posix_memalign(&local_page, 512, sat_->page_length());
#else
  local_page = memalign(512, sat_->page_length());
  int result = (local_page == 0);
#endif
  if (result) {
    logprintf(0, "Process Error: net slave posix_memalign "
                 "returned %d (fail)\n",
              result);
    status_ = false;
    return false;
  }

  struct page_entry page;
  page.addr = local_page;

  // This thread will continue to run as long as the thread on the other end of
  // the socket is still sending and receiving data.
  while (1) {
    // Do the network read.
    if (!ReceivePage(sock, &page))
      break;

    // Do the network write.
    if (!SendPage(sock, &page))
      break;

    loops++;
  }

  pages_copied_ = loops;
  // No results provided from this type of thread.
  status_ = true;

  // Clean up.
  CloseSocket(sock);

  logprintf(9,
            "Log: Completed %d: network slave thread status %d, "
            "%d pages copied\n",
            thread_num_, status_, pages_copied_);
  return true;
}

// Thread work loop. Execute until marked finished.
bool ErrorPollThread::Work() {
  logprintf(9, "Log: Starting system error poll thread %d\n", thread_num_);

  // This calls a generic error polling function in the Os abstraction layer.
  do {
    errorcount_ += os_->ErrorPoll();
    os_->ErrorWait();
  } while (IsReadyToRun());

  logprintf(9, "Log: Finished system error poll thread %d: %d errors\n",
            thread_num_, errorcount_);
  status_ = true;
  return true;
}

// Worker thread to heat up CPU.
// This thread does not evaluate pass/fail or software error.
bool CpuStressThread::Work() {
  logprintf(9, "Log: Starting CPU stress thread %d\n", thread_num_);

  do {
    // Run ludloff's platform/CPU-specific assembly workload.
    os_->CpuStressWorkload();
    YieldSelf();
  } while (IsReadyToRun());

  logprintf(9, "Log: Finished CPU stress thread %d:\n",
            thread_num_);
  status_ = true;
  return true;
}

CpuCacheCoherencyThread::CpuCacheCoherencyThread(cc_cacheline_data *data,
                                                 int cacheline_count,
                                                 int thread_num,
                                                 int inc_count) {
  cc_cacheline_data_ = data;
  cc_cacheline_count_ = cacheline_count;
  cc_thread_num_ = thread_num;
  cc_inc_count_ = inc_count;
}

// Worked thread to test the cache coherency of the CPUs
// Return false on fatal sw error.
bool CpuCacheCoherencyThread::Work() {
  logprintf(9, "Log: Starting the Cache Coherency thread %d\n",
            cc_thread_num_);
  uint64 time_start, time_end;
  struct timeval tv;

  unsigned int seed = static_cast<unsigned int>(gettid());
  gettimeofday(&tv, NULL);  // Get the timestamp before increments.
  time_start = tv.tv_sec * 1000000ULL + tv.tv_usec;

  uint64 total_inc = 0;  // Total increments done by the thread.
  while (IsReadyToRun()) {
    for (int i = 0; i < cc_inc_count_; i++) {
      // Choose a datastructure in random and increment the appropriate
      // member in that according to the offset (which is the same as the
      // thread number.
#ifdef HAVE_RAND_R
      int r = rand_r(&seed);
#else
      int r = rand();
#endif
      r = cc_cacheline_count_ * (r / (RAND_MAX + 1.0));
      // Increment the member of the randomely selected structure.
      (cc_cacheline_data_[r].num[cc_thread_num_])++;
    }

    total_inc += cc_inc_count_;

    // Calculate if the local counter matches with the global value
    // in all the cache line structures for this particular thread.
    int cc_global_num = 0;
    for (int cline_num = 0; cline_num < cc_cacheline_count_; cline_num++) {
      cc_global_num += cc_cacheline_data_[cline_num].num[cc_thread_num_];
      // Reset the cachline member's value for the next run.
      cc_cacheline_data_[cline_num].num[cc_thread_num_] = 0;
    }
    if (sat_->error_injection())
      cc_global_num = -1;

    if (cc_global_num != cc_inc_count_) {
      errorcount_++;
      logprintf(0, "Hardware Error: global(%d) and local(%d) do not match\n",
                cc_global_num, cc_inc_count_);
    }
  }
  gettimeofday(&tv, NULL);  // Get the timestamp at the end.
  time_end = tv.tv_sec * 1000000ULL + tv.tv_usec;

  uint64 us_elapsed = time_end - time_start;
  // inc_rate is the no. of increments per second.
  double inc_rate = total_inc * 1e6 / us_elapsed;

  logprintf(4, "Stats: CC Thread(%d): Time=%llu us,"
            " Increments=%llu, Increments/sec = %.6lf\n",
            cc_thread_num_, us_elapsed, total_inc, inc_rate);
  logprintf(9, "Log: Finished CPU Cache Coherency thread %d:\n",
            cc_thread_num_);
  status_ = true;
  return true;
}

DiskThread::DiskThread(DiskBlockTable *block_table) {
  read_block_size_ = kSectorSize;   // default 1 sector (512 bytes)
  write_block_size_ = kSectorSize;  // this assumes read and write block size
                                    // are the same
  segment_size_ = -1;               // use the entire disk as one segment
  cache_size_ = 16 * 1024 * 1024;   // assume 16MiB cache by default
  // Use a queue such that 3/2 times as much data as the cache can hold
  // is written before it is read so that there is little chance the read
  // data is in the cache.
  queue_size_ = ((cache_size_ / write_block_size_) * 3) / 2;
  blocks_per_segment_ = 32;

  read_threshold_ = 100000;         // 100ms is a reasonable limit for
  write_threshold_ = 100000;        // reading/writing a sector

  read_timeout_ = 5000000;          // 5 seconds should be long enough for a
  write_timeout_ = 5000000;         // timout for reading/writing

  device_sectors_ = 0;
  non_destructive_ = 0;

#ifdef HAVE_LIBAIO_H
  aio_ctx_ = 0;
#endif
  block_table_ = block_table;
  update_block_table_ = 1;

  block_buffer_ = NULL;

  blocks_written_ = 0;
  blocks_read_ = 0;
}

DiskThread::~DiskThread() {
  if (block_buffer_)
    free(block_buffer_);
}

// Set filename for device file (in /dev).
void DiskThread::SetDevice(const char *device_name) {
  device_name_ = device_name;
}

// Set various parameters that control the behaviour of the test.
// -1 is used as a sentinel value on each parameter (except non_destructive)
// to indicate that the parameter not be set.
bool DiskThread::SetParameters(int read_block_size,
                               int write_block_size,
                               int64 segment_size,
                               int64 cache_size,
                               int blocks_per_segment,
                               int64 read_threshold,
                               int64 write_threshold,
                               int non_destructive) {
  if (read_block_size != -1) {
    // Blocks must be aligned to the disk's sector size.
    if (read_block_size % kSectorSize != 0) {
      logprintf(0, "Process Error: Block size must be a multiple of %d "
                "(thread %d).\n", kSectorSize, thread_num_);
      return false;
    }

    read_block_size_ = read_block_size;
  }

  if (write_block_size != -1) {
    // Write blocks must be aligned to the disk's sector size and to the
    // block size.
    if (write_block_size % kSectorSize != 0) {
      logprintf(0, "Process Error: Write block size must be a multiple "
                "of %d (thread %d).\n", kSectorSize, thread_num_);
      return false;
    }
    if (write_block_size % read_block_size_ != 0) {
      logprintf(0, "Process Error: Write block size must be a multiple "
                "of the read block size, which is %d (thread %d).\n",
                read_block_size_, thread_num_);
      return false;
    }

    write_block_size_ = write_block_size;

  } else {
    // Make sure write_block_size_ is still valid.
    if (read_block_size_ > write_block_size_) {
      logprintf(5, "Log: Assuming write block size equal to read block size, "
                "which is %d (thread %d).\n", read_block_size_,
                thread_num_);
      write_block_size_ = read_block_size_;
    } else {
      if (write_block_size_ % read_block_size_ != 0) {
        logprintf(0, "Process Error: Write block size (defined as %d) must "
                  "be a multiple of the read block size, which is %d "
                  "(thread %d).\n", write_block_size_, read_block_size_,
                  thread_num_);
        return false;
      }
    }
  }

  if (cache_size != -1) {
    cache_size_ = cache_size;
  }

  if (blocks_per_segment != -1) {
    if (blocks_per_segment <= 0) {
      logprintf(0, "Process Error: Blocks per segment must be greater than "
                   "zero.\n (thread %d)", thread_num_);
      return false;
    }

    blocks_per_segment_ = blocks_per_segment;
  }

  if (read_threshold != -1) {
    if (read_threshold <= 0) {
      logprintf(0, "Process Error: Read threshold must be greater than "
                   "zero (thread %d).\n", thread_num_);
      return false;
    }

    read_threshold_ = read_threshold;
  }

  if (write_threshold != -1) {
    if (write_threshold <= 0) {
      logprintf(0, "Process Error: Write threshold must be greater than "
                   "zero (thread %d).\n", thread_num_);
      return false;
    }

    write_threshold_ = write_threshold;
  }

  if (segment_size != -1) {
    // Segments must be aligned to the disk's sector size.
    if (segment_size % kSectorSize != 0) {
      logprintf(0, "Process Error: Segment size must be a multiple of %d"
                " (thread %d).\n", kSectorSize, thread_num_);
      return false;
    }

    segment_size_ = segment_size / kSectorSize;
  }

  non_destructive_ = non_destructive;

  // Having a queue of 150% of blocks that will fit in the disk's cache
  // should be enough to force out the oldest block before it is read and hence,
  // making sure the data comes form the disk and not the cache.
  queue_size_ = ((cache_size_ / write_block_size_) * 3) / 2;
  // Updating DiskBlockTable parameters
  if (update_block_table_) {
    block_table_->SetParameters(kSectorSize, write_block_size_,
                                device_sectors_, segment_size_,
                                device_name_);
  }
  return true;
}

// Open a device, return false on failure.
bool DiskThread::OpenDevice(int *pfile) {
  bool no_O_DIRECT = false;
  int flags = O_RDWR | O_SYNC | O_LARGEFILE;
  int fd = open(device_name_.c_str(), flags | O_DIRECT, 0);
  if (O_DIRECT != 0 && fd < 0 && errno == EINVAL) {
    no_O_DIRECT = true;
    fd = open(device_name_.c_str(), flags, 0); // Try without O_DIRECT
  }
  if (fd < 0) {
    logprintf(0, "Process Error: Failed to open device %s (thread %d)!!\n",
              device_name_.c_str(), thread_num_);
    return false;
  }
  if (no_O_DIRECT)
    os_->ActivateFlushPageCache();
  *pfile = fd;

  return GetDiskSize(fd);
}

// Retrieves the size (in bytes) of the disk/file.
// Return false on failure.
bool DiskThread::GetDiskSize(int fd) {
  struct stat device_stat;
  if (fstat(fd, &device_stat) == -1) {
    logprintf(0, "Process Error: Unable to fstat disk %s (thread %d).\n",
              device_name_.c_str(), thread_num_);
    return false;
  }

  // For a block device, an ioctl is needed to get the size since the size
  // of the device file (i.e. /dev/sdb) is 0.
  if (S_ISBLK(device_stat.st_mode)) {
    uint64 block_size = 0;

    if (ioctl(fd, BLKGETSIZE64, &block_size) == -1) {
      logprintf(0, "Process Error: Unable to ioctl disk %s (thread %d).\n",
                device_name_.c_str(), thread_num_);
      return false;
    }

    // Zero size indicates nonworking device..
    if (block_size == 0) {
      os_->ErrorReport(device_name_.c_str(), "device-size-zero", 1);
      ++errorcount_;
      status_ = true;  // Avoid a procedural error.
      return false;
    }

    device_sectors_ = block_size / kSectorSize;

  } else if (S_ISREG(device_stat.st_mode)) {
    device_sectors_ = device_stat.st_size / kSectorSize;

  } else {
    logprintf(0, "Process Error: %s is not a regular file or block "
              "device (thread %d).\n", device_name_.c_str(),
              thread_num_);
    return false;
  }

  logprintf(12, "Log: Device sectors: %lld on disk %s (thread %d).\n",
            device_sectors_, device_name_.c_str(), thread_num_);

  if (update_block_table_) {
    block_table_->SetParameters(kSectorSize, write_block_size_,
                                device_sectors_, segment_size_,
                                device_name_);
  }

  return true;
}

bool DiskThread::CloseDevice(int fd) {
  close(fd);
  return true;
}

// Return the time in microseconds.
int64 DiskThread::GetTime() {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  return tv.tv_sec * 1000000 + tv.tv_usec;
}

// Do randomized reads and (possibly) writes on a device.
// Return false on fatal SW error, true on SW success,
// regardless of whether HW failed.
bool DiskThread::DoWork(int fd) {
  int64 block_num = 0;
  int64 num_segments;

  if (segment_size_ == -1) {
    num_segments = 1;
  } else {
    num_segments = device_sectors_ / segment_size_;
    if (device_sectors_ % segment_size_ != 0)
      num_segments++;
  }

  // Disk size should be at least 3x cache size.  See comment later for
  // details.
  sat_assert(device_sectors_ * kSectorSize > 3 * cache_size_);

  // This disk test works by writing blocks with a certain pattern to
  // disk, then reading them back and verifying it against the pattern
  // at a later time.  A failure happens when either the block cannot
  // be written/read or when the read block is different than what was
  // written.  If a block takes too long to write/read, then a warning
  // is given instead of an error since taking too long is not
  // necessarily an error.
  //
  // To prevent the read blocks from coming from the disk cache,
  // enough blocks are written before read such that a block would
  // be ejected from the disk cache by the time it is read.
  //
  // TODO(amistry): Implement some sort of read/write throttling.  The
  //                flood of asynchronous I/O requests when a drive is
  //                unplugged is causing the application and kernel to
  //                become unresponsive.

  while (IsReadyToRun()) {
    // Write blocks to disk.
    logprintf(16, "Log: Write phase %sfor disk %s (thread %d).\n",
              non_destructive_ ? "(disabled) " : "",
              device_name_.c_str(), thread_num_);
    while (IsReadyToRunNoPause() &&
           in_flight_sectors_.size() <
               static_cast<size_t>(queue_size_ + 1)) {
      // Confine testing to a particular segment of the disk.
      int64 segment = (block_num / blocks_per_segment_) % num_segments;
      if (!non_destructive_ &&
          (block_num % blocks_per_segment_ == 0)) {
        logprintf(20, "Log: Starting to write segment %lld out of "
                  "%lld on disk %s (thread %d).\n",
                  segment, num_segments, device_name_.c_str(),
                  thread_num_);
      }
      block_num++;

      BlockData *block = block_table_->GetUnusedBlock(segment);

      // If an unused sequence of sectors could not be found, skip to the
      // next block to process.  Soon, a new segment will come and new
      // sectors will be able to be allocated.  This effectively puts a
      // minumim on the disk size at 3x the stated cache size, or 48MiB
      // if a cache size is not given (since the cache is set as 16MiB
      // by default).  Given that todays caches are at the low MiB range
      // and drive sizes at the mid GB, this shouldn't pose a problem.
      // The 3x minimum comes from the following:
      //   1. In order to allocate 'y' blocks from a segment, the
      //      segment must contain at least 2y blocks or else an
      //      allocation may not succeed.
      //   2. Assume the entire disk is one segment.
      //   3. A full write phase consists of writing blocks corresponding to
      //      3/2 cache size.
      //   4. Therefore, the one segment must have 2 * 3/2 * cache
      //      size worth of blocks = 3 * cache size worth of blocks
      //      to complete.
      // In non-destructive mode, don't write anything to disk.
      if (!non_destructive_) {
        if (!WriteBlockToDisk(fd, block)) {
          block_table_->RemoveBlock(block);
          return true;
        }
        blocks_written_++;
      }

      // Block is either initialized by writing, or in nondestructive case,
      // initialized by being added into the datastructure for later reading.
      block->SetBlockAsInitialized();

      in_flight_sectors_.push(block);
    }
    if (!os_->FlushPageCache()) // If O_DIRECT worked, this will be a NOP.
      return false;

    // Verify blocks on disk.
    logprintf(20, "Log: Read phase for disk %s (thread %d).\n",
              device_name_.c_str(), thread_num_);
    while (IsReadyToRunNoPause() && !in_flight_sectors_.empty()) {
      BlockData *block = in_flight_sectors_.front();
      in_flight_sectors_.pop();
      if (!ValidateBlockOnDisk(fd, block))
        return true;
      block_table_->RemoveBlock(block);
      blocks_read_++;
    }
  }

  pages_copied_ = blocks_written_ + blocks_read_;
  return true;
}

// Do an asynchronous disk I/O operation.
// Return false if the IO is not set up.
bool DiskThread::AsyncDiskIO(IoOp op, int fd, void *buf, int64 size,
                            int64 offset, int64 timeout) {
#ifdef HAVE_LIBAIO_H
  // Use the Linux native asynchronous I/O interface for reading/writing.
  // A read/write consists of three basic steps:
  //    1. create an io context.
  //    2. prepare and submit an io request to the context
  //    3. wait for an event on the context.

  struct {
    const int opcode;
    const char *op_str;
    const char *error_str;
  } operations[2] = {
    { IO_CMD_PREAD, "read", "disk-read-error" },
    { IO_CMD_PWRITE, "write", "disk-write-error" }
  };

  struct iocb cb;
  memset(&cb, 0, sizeof(cb));

  cb.aio_fildes = fd;
  cb.aio_lio_opcode = operations[op].opcode;
  cb.u.c.buf = buf;
  cb.u.c.nbytes = size;
  cb.u.c.offset = offset;

  struct iocb *cbs[] = { &cb };
  if (io_submit(aio_ctx_, 1, cbs) != 1) {
    int error = errno;
    char buf[256];
    sat_strerror(error, buf, sizeof(buf));
    logprintf(0, "Process Error: Unable to submit async %s "
                 "on disk %s (thread %d). Error %d, %s\n",
              operations[op].op_str, device_name_.c_str(),
              thread_num_, error, buf);
    return false;
  }

  struct io_event event;
  memset(&event, 0, sizeof(event));
  struct timespec tv;
  tv.tv_sec = timeout / 1000000;
  tv.tv_nsec = (timeout % 1000000) * 1000;
  if (io_getevents(aio_ctx_, 1, 1, &event, &tv) != 1) {
    // A ctrl-c from the keyboard will cause io_getevents to fail with an
    // EINTR error code.  This is not an error and so don't treat it as such,
    // but still log it.
    int error = errno;
    if (error == EINTR) {
      logprintf(5, "Log: %s interrupted on disk %s (thread %d).\n",
                operations[op].op_str, device_name_.c_str(),
                thread_num_);
    } else {
      os_->ErrorReport(device_name_.c_str(), operations[op].error_str, 1);
      errorcount_ += 1;
      logprintf(0, "Hardware Error: Timeout doing async %s to sectors "
                   "starting at %lld on disk %s (thread %d).\n",
                operations[op].op_str, offset / kSectorSize,
                device_name_.c_str(), thread_num_);
    }

    // Don't bother checking return codes since io_cancel seems to always fail.
    // Since io_cancel is always failing, destroying and recreating an I/O
    // context is a workaround for canceling an in-progress I/O operation.
    // TODO(amistry): Find out why io_cancel isn't working and make it work.
    io_cancel(aio_ctx_, &cb, &event);
    io_destroy(aio_ctx_);
    aio_ctx_ = 0;
    if (io_setup(5, &aio_ctx_)) {
      int error = errno;
      char buf[256];
      sat_strerror(error, buf, sizeof(buf));
      logprintf(0, "Process Error: Unable to create aio context on disk %s"
                " (thread %d) Error %d, %s\n",
                device_name_.c_str(), thread_num_, error, buf);
    }

    return false;
  }

  // event.res contains the number of bytes written/read or
  // error if < 0, I think.
  if (event.res != static_cast<uint64>(size)) {
    errorcount_++;
    os_->ErrorReport(device_name_.c_str(), operations[op].error_str, 1);

    if (event.res < 0) {
      switch (event.res) {
        case -EIO:
          logprintf(0, "Hardware Error: Low-level I/O error while doing %s to "
                       "sectors starting at %lld on disk %s (thread %d).\n",
                    operations[op].op_str, offset / kSectorSize,
                    device_name_.c_str(), thread_num_);
          break;
        default:
          logprintf(0, "Hardware Error: Unknown error while doing %s to "
                       "sectors starting at %lld on disk %s (thread %d).\n",
                    operations[op].op_str, offset / kSectorSize,
                    device_name_.c_str(), thread_num_);
      }
    } else {
      logprintf(0, "Hardware Error: Unable to %s to sectors starting at "
                   "%lld on disk %s (thread %d).\n",
                operations[op].op_str, offset / kSectorSize,
                device_name_.c_str(), thread_num_);
    }
    return false;
  }

  return true;
#else // !HAVE_LIBAIO_H
  return false;
#endif
}

// Write a block to disk.
// Return false if the block is not written.
bool DiskThread::WriteBlockToDisk(int fd, BlockData *block) {
  memset(block_buffer_, 0, block->GetSize());

  // Fill block buffer with a pattern
  struct page_entry pe;
  if (!sat_->GetValid(&pe)) {
    // Even though a valid page could not be obatined, it is not an error
    // since we can always fill in a pattern directly, albeit slower.
    unsigned int *memblock = static_cast<unsigned int *>(block_buffer_);
    block->SetPattern(patternlist_->GetRandomPattern());

    logprintf(11, "Log: Warning, using pattern fill fallback in "
                  "DiskThread::WriteBlockToDisk on disk %s (thread %d).\n",
              device_name_.c_str(), thread_num_);

    for (int i = 0; i < block->GetSize()/wordsize_; i++) {
      memblock[i] = block->GetPattern()->pattern(i);
    }
  } else {
    memcpy(block_buffer_, pe.addr, block->GetSize());
    block->SetPattern(pe.pattern);
    sat_->PutValid(&pe);
  }

  logprintf(12, "Log: Writing %lld sectors starting at %lld on disk %s"
            " (thread %d).\n",
            block->GetSize()/kSectorSize, block->GetAddress(),
            device_name_.c_str(), thread_num_);

  int64 start_time = GetTime();

  if (!AsyncDiskIO(ASYNC_IO_WRITE, fd, block_buffer_, block->GetSize(),
                   block->GetAddress() * kSectorSize, write_timeout_)) {
    return false;
  }

  int64 end_time = GetTime();
  logprintf(12, "Log: Writing time: %lld us (thread %d).\n",
            end_time - start_time, thread_num_);
  if (end_time - start_time > write_threshold_) {
    logprintf(5, "Log: Write took %lld us which is longer than threshold "
                 "%lld us on disk %s (thread %d).\n",
              end_time - start_time, write_threshold_, device_name_.c_str(),
              thread_num_);
  }

  return true;
}

// Verify a block on disk.
// Return true if the block was read, also increment errorcount
// if the block had data errors or performance problems.
bool DiskThread::ValidateBlockOnDisk(int fd, BlockData *block) {
  int64 blocks = block->GetSize() / read_block_size_;
  int64 bytes_read = 0;
  int64 current_blocks;
  int64 current_bytes;
  uint64 address = block->GetAddress();

  logprintf(20, "Log: Reading sectors starting at %lld on disk %s "
            "(thread %d).\n",
            address, device_name_.c_str(), thread_num_);

  // Read block from disk and time the read.  If it takes longer than the
  // threshold, complain.
  if (lseek64(fd, address * kSectorSize, SEEK_SET) == -1) {
    logprintf(0, "Process Error: Unable to seek to sector %lld in "
              "DiskThread::ValidateSectorsOnDisk on disk %s "
              "(thread %d).\n", address, device_name_.c_str(), thread_num_);
    return false;
  }
  int64 start_time = GetTime();

  // Split a large write-sized block into small read-sized blocks and
  // read them in groups of randomly-sized multiples of read block size.
  // This assures all data written on disk by this particular block
  // will be tested using a random reading pattern.
  while (blocks != 0) {
    // Test all read blocks in a written block.
    current_blocks = (random() % blocks) + 1;
    current_bytes = current_blocks * read_block_size_;

    memset(block_buffer_, 0, current_bytes);

    logprintf(20, "Log: Reading %lld sectors starting at sector %lld on "
              "disk %s (thread %d)\n",
              current_bytes / kSectorSize,
              (address * kSectorSize + bytes_read) / kSectorSize,
              device_name_.c_str(), thread_num_);

    if (!AsyncDiskIO(ASYNC_IO_READ, fd, block_buffer_, current_bytes,
                     address * kSectorSize + bytes_read,
                     write_timeout_)) {
      return false;
    }

    int64 end_time = GetTime();
    logprintf(20, "Log: Reading time: %lld us (thread %d).\n",
              end_time - start_time, thread_num_);
    if (end_time - start_time > read_threshold_) {
      logprintf(5, "Log: Read took %lld us which is longer than threshold "
                "%lld us on disk %s (thread %d).\n",
                end_time - start_time, read_threshold_,
                device_name_.c_str(), thread_num_);
    }

    // In non-destructive mode, don't compare the block to the pattern since
    // the block was never written to disk in the first place.
    if (!non_destructive_) {
      if (CheckRegion(block_buffer_, block->GetPattern(), current_bytes,
                      0, bytes_read)) {
        os_->ErrorReport(device_name_.c_str(), "disk-pattern-error", 1);
        errorcount_ += 1;
        logprintf(0, "Hardware Error: Pattern mismatch in block starting at "
                  "sector %lld in DiskThread::ValidateSectorsOnDisk on "
                  "disk %s (thread %d).\n",
                  address, device_name_.c_str(), thread_num_);
      }
    }

    bytes_read += current_blocks * read_block_size_;
    blocks -= current_blocks;
  }

  return true;
}

// Direct device access thread.
// Return false on software error.
bool DiskThread::Work() {
  int fd;

  logprintf(9, "Log: Starting disk thread %d, disk %s\n",
            thread_num_, device_name_.c_str());

  srandom(time(NULL));

  if (!OpenDevice(&fd)) {
    status_ = false;
    return false;
  }

  // Allocate a block buffer aligned to 512 bytes since the kernel requires it
  // when using direct IO.
#ifdef HAVE_POSIX_MEMALIGN
  int memalign_result = posix_memalign(&block_buffer_, kBufferAlignment,
                              sat_->page_length());
#else
  block_buffer_ = memalign(kBufferAlignment, sat_->page_length());
  int memalign_result = (block_buffer_ == 0);
#endif
  if (memalign_result) {
    CloseDevice(fd);
    logprintf(0, "Process Error: Unable to allocate memory for buffers "
                 "for disk %s (thread %d) posix memalign returned %d.\n",
              device_name_.c_str(), thread_num_, memalign_result);
    status_ = false;
    return false;
  }

#ifdef HAVE_LIBAIO_H
  if (io_setup(5, &aio_ctx_)) {
    CloseDevice(fd);
    logprintf(0, "Process Error: Unable to create aio context for disk %s"
              " (thread %d).\n",
              device_name_.c_str(), thread_num_);
    status_ = false;
    return false;
  }
#endif

  bool result = DoWork(fd);

  status_ = result;

#ifdef HAVE_LIBAIO_H
  io_destroy(aio_ctx_);
#endif
  CloseDevice(fd);

  logprintf(9, "Log: Completed %d (disk %s): disk thread status %d, "
               "%d pages copied\n",
            thread_num_, device_name_.c_str(), status_, pages_copied_);
  return result;
}

RandomDiskThread::RandomDiskThread(DiskBlockTable *block_table)
    : DiskThread(block_table) {
  update_block_table_ = 0;
}

RandomDiskThread::~RandomDiskThread() {
}

// Workload for random disk thread.
bool RandomDiskThread::DoWork(int fd) {
  logprintf(11, "Log: Random phase for disk %s (thread %d).\n",
            device_name_.c_str(), thread_num_);
  while (IsReadyToRun()) {
    BlockData *block = block_table_->GetRandomBlock();
    if (block == NULL) {
      logprintf(12, "Log: No block available for device %s (thread %d).\n",
                device_name_.c_str(), thread_num_);
    } else {
      ValidateBlockOnDisk(fd, block);
      block_table_->ReleaseBlock(block);
      blocks_read_++;
    }
  }
  pages_copied_ = blocks_read_;
  return true;
}

MemoryRegionThread::MemoryRegionThread() {
  error_injection_ = false;
  pages_ = NULL;
}

MemoryRegionThread::~MemoryRegionThread() {
  if (pages_ != NULL)
    delete pages_;
}

// Set a region of memory or MMIO to be tested.
// Return false if region could not be mapped.
bool MemoryRegionThread::SetRegion(void *region, int64 size) {
  int plength = sat_->page_length();
  int npages = size / plength;
  if (size % plength) {
    logprintf(0, "Process Error: region size is not a multiple of SAT "
              "page length\n");
    return false;
  } else {
    if (pages_ != NULL)
      delete pages_;
    pages_ = new PageEntryQueue(npages);
    char *base_addr = reinterpret_cast<char*>(region);
    region_ = base_addr;
    for (int i = 0; i < npages; i++) {
      struct page_entry pe;
      init_pe(&pe);
      pe.addr = reinterpret_cast<void*>(base_addr + i * plength);
      pe.offset = i * plength;

      pages_->Push(&pe);
    }
    return true;
  }
}

// More detailed error printout for hardware errors in memory or MMIO
// regions.
void MemoryRegionThread::ProcessError(struct ErrorRecord *error,
                                      int priority,
                                      const char *message) {
  uint32 buffer_offset;
  if (phase_ == kPhaseCopy) {
    // If the error occurred on the Copy Phase, it means that
    // the source data (i.e., the main memory) is wrong. so
    // just pass it to the original ProcessError to call a
    // bad-dimm error
    WorkerThread::ProcessError(error, priority, message);
  } else if (phase_ == kPhaseCheck) {
    // A error on the Check Phase means that the memory region tested
    // has an error. Gathering more information and then reporting
    // the error.
    // Determine if this is a write or read error.
    os_->Flush(error->vaddr);
    error->reread = *(error->vaddr);
    char *good = reinterpret_cast<char*>(&(error->expected));
    char *bad = reinterpret_cast<char*>(&(error->actual));
    sat_assert(error->expected != error->actual);
    unsigned int offset = 0;
    for (offset = 0; offset < (sizeof(error->expected) - 1); offset++) {
      if (good[offset] != bad[offset])
        break;
    }

    error->vbyteaddr = reinterpret_cast<char*>(error->vaddr) + offset;

    buffer_offset = error->vbyteaddr - region_;

    // Find physical address if possible.
    error->paddr = os_->VirtualToPhysical(error->vbyteaddr);
    logprintf(priority,
              "%s: miscompare on %s, CRC check at %p(0x%llx), "
              "offset %llx: read:0x%016llx, reread:0x%016llx "
              "expected:0x%016llx\n",
              message,
              identifier_.c_str(),
              error->vaddr,
              error->paddr,
              buffer_offset,
              error->actual,
              error->reread,
              error->expected);
  } else {
    logprintf(0, "Process Error: memory region thread raised an "
              "unexpected error.");
  }
}

// Workload for testion memory or MMIO regions.
// Return false on software error.
bool MemoryRegionThread::Work() {
  struct page_entry source_pe;
  struct page_entry memregion_pe;
  bool result = true;
  int64 loops = 0;
  const uint64 error_constant = 0x00ba00000000ba00LL;

  // For error injection.
  int64 *addr = 0x0;
  int offset = 0;
  int64 data = 0;

  logprintf(9, "Log: Starting Memory Region thread %d\n", thread_num_);

  while (IsReadyToRun()) {
    // Getting pages from SAT and queue.
    phase_ = kPhaseNoPhase;
    result = result && sat_->GetValid(&source_pe);
    if (!result) {
      logprintf(0, "Process Error: memory region thread failed to pop "
                "pages from SAT, bailing\n");
      break;
    }

    result = result && pages_->PopRandom(&memregion_pe);
    if (!result) {
      logprintf(0, "Process Error: memory region thread failed to pop "
                "pages from queue, bailing\n");
      break;
    }

    // Error injection for CRC copy.
    if ((sat_->error_injection() || error_injection_) && loops == 1) {
      addr = reinterpret_cast<int64*>(source_pe.addr);
      offset = random() % (sat_->page_length() / wordsize_);
      data = addr[offset];
      addr[offset] = error_constant;
    }

    // Copying SAT page into memory region.
    phase_ = kPhaseCopy;
    CrcCopyPage(&memregion_pe, &source_pe);
    memregion_pe.pattern = source_pe.pattern;

    // Error injection for CRC Check.
    if ((sat_->error_injection() || error_injection_) && loops == 2) {
      addr = reinterpret_cast<int64*>(memregion_pe.addr);
      offset = random() % (sat_->page_length() / wordsize_);
      data = addr[offset];
      addr[offset] = error_constant;
    }

    // Checking page content in memory region.
    phase_ = kPhaseCheck;
    CrcCheckPage(&memregion_pe);

    phase_ = kPhaseNoPhase;
    // Storing pages on their proper queues.
    result = result && sat_->PutValid(&source_pe);
    if (!result) {
      logprintf(0, "Process Error: memory region thread failed to push "
                "pages into SAT, bailing\n");
      break;
    }
    result = result && pages_->Push(&memregion_pe);
    if (!result) {
      logprintf(0, "Process Error: memory region thread failed to push "
                "pages into queue, bailing\n");
      break;
    }

    if ((sat_->error_injection() || error_injection_) &&
        loops >= 1 && loops <= 2) {
      addr[offset] = data;
    }

    loops++;
    YieldSelf();
  }

  pages_copied_ = loops;
  status_ = result;
  logprintf(9, "Log: Completed %d: Memory Region thread. Status %d, %d "
            "pages checked\n", thread_num_, status_, pages_copied_);
  return result;
}
