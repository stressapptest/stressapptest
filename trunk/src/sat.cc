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

// sat.cc : a stress test for stressful testing

// stressapptest (or SAT, from Stressful Application Test) is a test
// designed to stress the system, as well as provide a comprehensive
// memory interface test.

// stressapptest can be run using memory only, or using many system components.

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/times.h>

// #define __USE_GNU
// #define __USE_LARGEFILE64
#include <fcntl.h>

#include <list>
#include <string>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "disk_blocks.h"
#include "logger.h"
#include "os.h"
#include "sat.h"
#include "sattypes.h"
#include "worker.h"

// stressapptest versioning here.
#ifndef PACKAGE_VERSION
static const char* kVersion = "1.0.0";
#else
static const char* kVersion = PACKAGE_VERSION;
#endif

// Global stressapptest reference, for use by signal handler.
// This makes Sat objects not safe for multiple instances.
namespace {
  Sat *g_sat = NULL;

  // Signal handler for catching break or kill.
  //
  // This must be installed after g_sat is assigned and while there is a single
  // thread.
  //
  // This must be uninstalled while there is only a single thread, and of course
  // before g_sat is cleared or deleted.
  void SatHandleBreak(int signal) {
    g_sat->Break();
  }
}

// Opens the logfile for writing if necessary
bool Sat::InitializeLogfile() {
  // Open logfile.
  if (use_logfile_) {
    logfile_ = open(logfilename_,
#if defined(O_DSYNC)
                    O_DSYNC |
#elif defined(O_SYNC)
                    O_SYNC |
#elif defined(O_FSYNC)
                    O_FSYNC |
#endif
                    O_WRONLY | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (logfile_ < 0) {
      printf("Fatal Error: cannot open file %s for logging\n",
             logfilename_);
      bad_status();
      return false;
    }
    // We seek to the end once instead of opening in append mode because no
    // other processes should be writing to it while this one exists.
    if (lseek(logfile_, 0, SEEK_END) == -1) {
      printf("Fatal Error: cannot seek to end of logfile (%s)\n",
             logfilename_);
      bad_status();
      return false;
    }
    Logger::GlobalLogger()->SetLogFd(logfile_);
  }
  return true;
}

// Check that the environment is known and safe to run on.
// Return 1 if good, 0 if unsuppported.
bool Sat::CheckEnvironment() {
  // Check that this is not a debug build. Debug builds lack
  // enough performance to stress the system.
#if !defined NDEBUG
  if (run_on_anything_) {
    logprintf(1, "Log: Running DEBUG version of SAT, "
                 "with significantly reduced coverage.\n");
  } else {
    logprintf(0, "Process Error: Running DEBUG version of SAT, "
                 "with significantly reduced coverage.\n");
    logprintf(0, "Log: Command line option '-A' bypasses this error.\n");
    bad_status();
    return false;
  }
#elif !defined CHECKOPTS
  #error Build system regression - COPTS disregarded.
#endif

  // Use all CPUs if nothing is specified.
  if (memory_threads_ == -1) {
    memory_threads_ = os_->num_cpus();
    logprintf(7, "Log: Defaulting to %d copy threads\n", memory_threads_);
  }

  // Use all memory if no size is specified.
  if (size_mb_ == 0)
    size_mb_ = os_->FindFreeMemSize() / kMegabyte;
  size_ = static_cast<int64>(size_mb_) * kMegabyte;

  // Autodetect file locations.
  if (findfiles_ && (file_threads_ == 0)) {
    // Get a space separated sting of disk locations.
    list<string> locations = os_->FindFileDevices();

    // Extract each one.
    while (!locations.empty()) {
      // Copy and remove the disk name.
      string disk = locations.back();
      locations.pop_back();

      logprintf(12, "Log: disk at %s\n", disk.c_str());
      file_threads_++;
      filename_.push_back(disk + "/sat_disk.a");
      file_threads_++;
      filename_.push_back(disk + "/sat_disk.b");
    }
  }

  // We'd better have some memory by this point.
  if (size_ < 1) {
    logprintf(0, "Process Error: No memory found to test.\n");
    bad_status();
    return false;
  }

  if (tag_mode_ && ((file_threads_ > 0) ||
                    (disk_threads_ > 0) ||
                    (net_threads_ > 0))) {
    logprintf(0, "Process Error: Memory tag mode incompatible "
                 "with disk/network DMA.\n");
    bad_status();
    return false;
  }

  // If platform is 32 bit Xeon, floor memory size to multiple of 4.
  if (address_mode_ == 32) {
    size_mb_ = (size_mb_ / 4) * 4;
    size_ = size_mb_ * kMegabyte;
    logprintf(1, "Log: Flooring memory allocation to multiple of 4: %lldMB\n",
              size_mb_);
  }

  // Check if this system is on the whitelist for supported systems.
  if (!os_->IsSupported()) {
    if (run_on_anything_) {
      logprintf(1, "Log: Unsupported system. Running with reduced coverage.\n");
      // This is ok, continue on.
    } else {
      logprintf(0, "Process Error: Unsupported system, "
                   "no error reporting available\n");
      logprintf(0, "Log: Command line option '-A' bypasses this error.\n");
      bad_status();
      return false;
    }
  }

  return true;
}

// Allocates memory to run the test on
bool Sat::AllocateMemory() {
  // Allocate our test memory.
  bool result = os_->AllocateTestMem(size_, paddr_base_);
  if (!result) {
    logprintf(0, "Process Error: failed to allocate memory\n");
    bad_status();
    return false;
  }
  return true;
}

// Sets up access to data patterns
bool Sat::InitializePatterns() {
  // Initialize pattern data.
  patternlist_ = new PatternList();
  if (!patternlist_) {
    logprintf(0, "Process Error: failed to allocate patterns\n");
    bad_status();
    return false;
  }
  if (!patternlist_->Initialize()) {
    logprintf(0, "Process Error: failed to initialize patternlist\n");
    bad_status();
    return false;
  }
  return true;
}

// Get any valid page, no tag specified.
bool Sat::GetValid(struct page_entry *pe) {
  return GetValid(pe, kDontCareTag);
}


// Fetch and return empty and full pages into the empty and full pools.
bool Sat::GetValid(struct page_entry *pe, int32 tag) {
  bool result = false;
  // Get valid page depending on implementation.
  if (pe_q_implementation_ == SAT_FINELOCK)
    result = finelock_q_->GetValid(pe, tag);
  else if (pe_q_implementation_ == SAT_ONELOCK)
    result = valid_->PopRandom(pe);

  if (result) {
    pe->addr = os_->PrepareTestMem(pe->offset, page_length_);  // Map it.

    // Tag this access and current pattern.
    pe->ts = os_->GetTimestamp();
    pe->lastpattern = pe->pattern;

    return (pe->addr != 0);     // Return success or failure.
  }
  return false;
}

bool Sat::PutValid(struct page_entry *pe) {
  if (pe->addr != 0)
    os_->ReleaseTestMem(pe->addr, pe->offset, page_length_);  // Unmap the page.
  pe->addr = 0;

  // Put valid page depending on implementation.
  if (pe_q_implementation_ == SAT_FINELOCK)
    return finelock_q_->PutValid(pe);
  else if (pe_q_implementation_ == SAT_ONELOCK)
    return valid_->Push(pe);
  else
    return false;
}

// Get an empty page with any tag.
bool Sat::GetEmpty(struct page_entry *pe) {
  return GetEmpty(pe, kDontCareTag);
}

bool Sat::GetEmpty(struct page_entry *pe, int32 tag) {
  bool result = false;
  // Get empty page depending on implementation.
  if (pe_q_implementation_ == SAT_FINELOCK)
    result = finelock_q_->GetEmpty(pe, tag);
  else if (pe_q_implementation_ == SAT_ONELOCK)
    result = empty_->PopRandom(pe);

  if (result) {
    pe->addr = os_->PrepareTestMem(pe->offset, page_length_);  // Map it.
    return (pe->addr != 0);     // Return success or failure.
  }
  return false;
}

bool Sat::PutEmpty(struct page_entry *pe) {
  if (pe->addr != 0)
    os_->ReleaseTestMem(pe->addr, pe->offset, page_length_);  // Unmap the page.
  pe->addr = 0;

  // Put empty page depending on implementation.
  if (pe_q_implementation_ == SAT_FINELOCK)
    return finelock_q_->PutEmpty(pe);
  else if (pe_q_implementation_ == SAT_ONELOCK)
    return empty_->Push(pe);
  else
    return false;
}

// Set up the bitmap of physical pages in case we want to see which pages were
// accessed under this run of SAT.
void Sat::AddrMapInit() {
  if (!do_page_map_)
    return;
  // Find about how much physical mem is in the system.
  // TODO(nsanders): Find some way to get the max
  // and min phys addr in the system.
  uint64 maxsize = os_->FindFreeMemSize() * 4;
  sat_assert(maxsize != 0);

  // Make a bitmask of this many pages. Assume that the memory is relatively
  // zero based. This is true on x86, typically.
  // This is one bit per page.
  uint64 arraysize = maxsize / 4096 / 8;
  unsigned char *bitmap = new unsigned char[arraysize];
  sat_assert(bitmap);

  // Mark every page as 0, not seen.
  memset(bitmap, 0, arraysize);

  page_bitmap_size_ = maxsize;
  page_bitmap_ = bitmap;
}

// Add the 4k pages in this block to the array of pages SAT has seen.
void Sat::AddrMapUpdate(struct page_entry *pe) {
  if (!do_page_map_)
    return;

  // Go through 4k page blocks.
  uint64 arraysize = page_bitmap_size_ / 4096 / 8;

  char *base = reinterpret_cast<char*>(pe->addr);
  for (int i = 0; i < page_length_; i += 4096) {
    uint64 paddr = os_->VirtualToPhysical(base + i);

    uint32 offset = paddr / 4096 / 8;
    unsigned char mask = 1 << ((paddr / 4096) % 8);

    if (offset >= arraysize) {
      logprintf(0, "Process Error: Physical address %#llx is "
                   "greater than expected %#llx.\n",
                paddr, page_bitmap_size_);
      sat_assert(0);
    }
    page_bitmap_[offset] |= mask;
  }
}

// Print out the physical memory ranges that SAT has accessed.
void Sat::AddrMapPrint() {
  if (!do_page_map_)
    return;

  uint64 pages = page_bitmap_size_ / 4096;

  uint64 last_page = 0;
  bool valid_range = false;

  logprintf(4, "Log: Printing tested physical ranges.\n");

  for (uint64 i = 0; i < pages; i ++) {
    int offset = i / 8;
    unsigned char mask = 1 << (i % 8);

    bool touched = page_bitmap_[offset] & mask;
    if (touched && !valid_range) {
      valid_range = true;
      last_page = i * 4096;
    } else if (!touched && valid_range) {
      valid_range = false;
      logprintf(4, "Log: %#016llx - %#016llx\n", last_page, (i * 4096) - 1);
    }
  }
  logprintf(4, "Log: Done printing physical ranges.\n");
}

// Initializes page lists and fills pages with data patterns.
bool Sat::InitializePages() {
  int result = 1;
  // Calculate needed page totals.
  int64 neededpages = memory_threads_ +
    invert_threads_ +
    check_threads_ +
    net_threads_ +
    file_threads_;

  // Empty-valid page ratio is adjusted depending on queue implementation.
  // since fine-grain-locked queue keeps both valid and empty entries in the
  // same queue and randomly traverse to find pages, the empty-valid ratio
  // should be more even.
  if (pe_q_implementation_ == SAT_FINELOCK)
    freepages_ = pages_ / 5 * 2;  // Mark roughly 2/5 of all pages as Empty.
  else
    freepages_ = (pages_ / 100) + (2 * neededpages);

  if (freepages_ < neededpages) {
    logprintf(0, "Process Error: freepages < neededpages.\n");
    logprintf(1, "Stats: Total: %lld, Needed: %lld, Marked free: %lld\n",
              static_cast<int64>(pages_),
              static_cast<int64>(neededpages),
              static_cast<int64>(freepages_));
    bad_status();
    return false;
  }

  if (freepages_ >  pages_/2) {
    logprintf(0, "Process Error: not enough pages for IO\n");
    logprintf(1, "Stats: Total: %lld, Needed: %lld, Available: %lld\n",
              static_cast<int64>(pages_),
              static_cast<int64>(freepages_),
              static_cast<int64>(pages_/2));
    bad_status();
    return false;
  }
  logprintf(12, "Log: Allocating pages, Total: %lld Free: %lld\n",
            pages_,
            freepages_);

  // Initialize page locations.
  for (int64 i = 0; i < pages_; i++) {
    struct page_entry pe;
    init_pe(&pe);
    pe.offset = i * page_length_;
    result &= PutEmpty(&pe);
  }

  if (!result) {
    logprintf(0, "Process Error: while initializing empty_ list\n");
    bad_status();
    return false;
  }

  // Fill valid pages with test patterns.
  // Use fill threads to do this.
  WorkerStatus fill_status;
  WorkerVector fill_vector;

  logprintf(12, "Starting Fill threads: %d threads, %d pages\n",
            fill_threads_, pages_);
  // Initialize the fill threads.
  for (int i = 0; i < fill_threads_; i++) {
    FillThread *thread = new FillThread();
    thread->InitThread(i, this, os_, patternlist_, &fill_status);
    if (i != fill_threads_ - 1) {
        logprintf(12, "Starting Fill Threads %d: %d pages\n",
                  i, pages_ / fill_threads_);
        thread->SetFillPages(pages_ / fill_threads_);
      // The last thread finishes up all the leftover pages.
    } else {
      logprintf(12, "Starting Fill Threads %d: %d pages\n",
                i, pages_ - pages_ / fill_threads_ * i);
        thread->SetFillPages(pages_ - pages_ / fill_threads_ * i);
    }
    fill_vector.push_back(thread);
  }

  // Spawn the fill threads.
  fill_status.Initialize();
  for (WorkerVector::const_iterator it = fill_vector.begin();
       it != fill_vector.end(); ++it)
    (*it)->SpawnThread();

  // Reap the finished fill threads.
  for (WorkerVector::const_iterator it = fill_vector.begin();
       it != fill_vector.end(); ++it) {
    (*it)->JoinThread();
    if ((*it)->GetStatus() != 1) {
      logprintf(0, "Thread %d failed with status %d at %.2f seconds\n",
                (*it)->ThreadID(), (*it)->GetStatus(),
                (*it)->GetRunDurationUSec() * 1.0/1000000);
      bad_status();
      return false;
    }
    delete (*it);
  }
  fill_vector.clear();
  fill_status.Destroy();
  logprintf(12, "Log: Done filling pages.\n");
  logprintf(12, "Log: Allocating pages.\n");

  AddrMapInit();

  // Initialize page locations.
  for (int64 i = 0; i < pages_; i++) {
    struct page_entry pe;
    // Only get valid pages with uninitialized tags here.
    char buf[256];
    if (GetValid(&pe, kInvalidTag)) {
      int64 paddr = os_->VirtualToPhysical(pe.addr);
      int32 region = os_->FindRegion(paddr);

      os_->FindDimm(paddr, buf, sizeof(buf));
      if (i < 256) {
        logprintf(12, "Log: address: %#llx, %s\n", paddr, buf);
      }
      region_[region]++;
      pe.paddr = paddr;
      pe.tag = 1 << region;
      region_mask_ |= pe.tag;

      // Generate a physical region map
      AddrMapUpdate(&pe);

      // Note: this does not allocate free pages among all regions
      // fairly. However, with large enough (thousands) random number
      // of pages being marked free in each region, the free pages
      // count in each region end up pretty balanced.
      if (i < freepages_) {
        result &= PutEmpty(&pe);
      } else {
        result &= PutValid(&pe);
      }
    } else {
      logprintf(0, "Log: didn't tag all pages. %d - %d = %d\n",
                pages_, i, pages_ - i);
      return false;
    }
  }
  logprintf(12, "Log: Done allocating pages.\n");

  AddrMapPrint();

  for (int i = 0; i < 32; i++) {
    if (region_mask_ & (1 << i)) {
      region_count_++;
      logprintf(12, "Log: Region %d: %d.\n", i, region_[i]);
    }
  }
  logprintf(5, "Log: Region mask: 0x%x\n", region_mask_);

  return true;
}

// Print SAT version info.
bool Sat::PrintVersion() {
  logprintf(1, "Stats: SAT revision %s, %d bit binary\n",
            kVersion, address_mode_);
  logprintf(5, "Log: %s from %s\n", Timestamp(), BuildChangelist());

  return true;
}


// Initializes the resources that SAT needs to run.
// This needs to be called before Run(), and after ParseArgs().
// Returns true on success, false on error, and will exit() on help message.
bool Sat::Initialize() {
  g_sat = this;

  // Initializes sync'd log file to ensure output is saved.
  if (!InitializeLogfile())
    return false;
  Logger::GlobalLogger()->StartThread();

  logprintf(5, "Log: Commandline - %s\n", cmdline_.c_str());
  PrintVersion();

  std::map<std::string, std::string> options;

  GoogleOsOptions(&options);

  // Initialize OS/Hardware interface.
  os_ = OsLayerFactory(options);
  if (!os_) {
    bad_status();
    return false;
  }

  if (min_hugepages_mbytes_ > 0)
    os_->SetMinimumHugepagesSize(min_hugepages_mbytes_ * kMegabyte);

  if (!os_->Initialize()) {
    logprintf(0, "Process Error: Failed to initialize OS layer\n");
    bad_status();
    delete os_;
    return false;
  }

  // Checks that OS/Build/Platform is supported.
  if (!CheckEnvironment())
    return false;

  if (error_injection_)
    os_->set_error_injection(true);

  // Run SAT in monitor only mode, do not continue to allocate resources.
  if (monitor_mode_) {
    logprintf(5, "Log: Running in monitor-only mode. "
                 "Will not allocate any memory nor run any stress test. "
                 "Only polling ECC errors.\n");
    return true;
  }

  // Allocate the memory to test.
  if (!AllocateMemory())
    return false;

  logprintf(5, "Stats: Starting SAT, %dM, %d seconds\n",
            static_cast<int>(size_/kMegabyte),
            runtime_seconds_);

  if (!InitializePatterns())
    return false;

  // Initialize memory allocation.
  pages_ = size_ / page_length_;

  // Allocate page queue depending on queue implementation switch.
  if (pe_q_implementation_ == SAT_FINELOCK) {
      finelock_q_ = new FineLockPEQueue(pages_, page_length_);
      if (finelock_q_ == NULL)
        return false;
      finelock_q_->set_os(os_);
      os_->set_err_log_callback(finelock_q_->get_err_log_callback());
  } else if (pe_q_implementation_ == SAT_ONELOCK) {
      empty_ = new PageEntryQueue(pages_);
      valid_ = new PageEntryQueue(pages_);
      if ((empty_ == NULL) || (valid_ == NULL))
        return false;
  }

  if (!InitializePages()) {
    logprintf(0, "Process Error: Initialize Pages failed\n");
    return false;
  }

  return true;
}

// Constructor and destructor.
Sat::Sat() {
  // Set defaults, command line might override these.
  runtime_seconds_ = 20;
  page_length_ = kSatPageSize;
  disk_pages_ = kSatDiskPage;
  pages_ = 0;
  size_mb_ = 0;
  size_ = size_mb_ * kMegabyte;
  min_hugepages_mbytes_ = 0;
  freepages_ = 0;
  paddr_base_ = 0;

  user_break_ = false;
  verbosity_ = 8;
  Logger::GlobalLogger()->SetVerbosity(verbosity_);
  strict_ = 1;
  warm_ = 0;
  run_on_anything_ = 0;
  use_logfile_ = 0;
  logfile_ = 0;
  // Detect 32/64 bit binary.
  void *pvoid = 0;
  address_mode_ = sizeof(pvoid) * 8;
  error_injection_ = false;
  crazy_error_injection_ = false;
  max_errorcount_ = 0;  // Zero means no early exit.
  stop_on_error_ = false;
  error_poll_ = true;
  findfiles_ = false;

  do_page_map_ = false;
  page_bitmap_ = 0;
  page_bitmap_size_ = 0;

  // Cache coherency data initialization.
  cc_test_ = false;         // Flag to trigger cc threads.
  cc_cacheline_count_ = 2;  // Two datastructures of cache line size.
  cc_inc_count_ = 1000;     // Number of times to increment the shared variable.
  cc_cacheline_data_ = 0;   // Cache Line size datastructure.

  sat_assert(0 == pthread_mutex_init(&worker_lock_, NULL));
  file_threads_ = 0;
  net_threads_ = 0;
  listen_threads_ = 0;
  // Default to autodetect number of cpus, and run that many threads.
  memory_threads_ = -1;
  invert_threads_ = 0;
  fill_threads_ = 8;
  check_threads_ = 0;
  cpu_stress_threads_ = 0;
  disk_threads_ = 0;
  total_threads_ = 0;

  region_mask_ = 0;
  region_count_ = 0;
  for (int i = 0; i < 32; i++) {
    region_[i] = 0;
  }
  region_mode_ = 0;

  errorcount_ = 0;
  statuscount_ = 0;

  valid_ = 0;
  empty_ = 0;
  finelock_q_ = 0;
  // Default to use fine-grain lock for better performance.
  pe_q_implementation_ = SAT_FINELOCK;

  os_ = 0;
  patternlist_ = 0;
  logfilename_[0] = 0;

  read_block_size_ = 512;
  write_block_size_ = -1;
  segment_size_ = -1;
  cache_size_ = -1;
  blocks_per_segment_ = -1;
  read_threshold_ = -1;
  write_threshold_ = -1;
  non_destructive_ = 1;
  monitor_mode_ = 0;
  tag_mode_ = 0;
  random_threads_ = 0;

  pause_delay_ = 600;
  pause_duration_ = 15;
}

// Destructor.
Sat::~Sat() {
  // We need to have called Cleanup() at this point.
  // We should probably enforce this.
}


#define ARG_KVALUE(argument, variable, value)         \
  if (!strcmp(argv[i], argument)) {                   \
    variable = value;                                 \
    continue;                                         \
  }

#define ARG_IVALUE(argument, variable)                \
  if (!strcmp(argv[i], argument)) {                   \
    i++;                                              \
    if (i < argc)                                     \
      variable = strtoull(argv[i], NULL, 0);          \
    continue;                                         \
  }

#define ARG_SVALUE(argument, variable)                     \
  if (!strcmp(argv[i], argument)) {                        \
    i++;                                                   \
    if (i < argc)                                          \
      snprintf(variable, sizeof(variable), "%s", argv[i]); \
    continue;                                              \
  }

// Configures SAT from command line arguments.
// This will call exit() given a request for
// self-documentation or unexpected args.
bool Sat::ParseArgs(int argc, char **argv) {
  int i;
  uint64 filesize = page_length_ * disk_pages_;

  // Parse each argument.
  for (i = 1; i < argc; i++) {
    // Switch to fall back to corase-grain-lock queue. (for benchmarking)
    ARG_KVALUE("--coarse_grain_lock", pe_q_implementation_, SAT_ONELOCK);

    // Set number of megabyte to use.
    ARG_IVALUE("-M", size_mb_);

    // Set minimum megabytes of hugepages to require.
    ARG_IVALUE("-H", min_hugepages_mbytes_);

    // Set number of seconds to run.
    ARG_IVALUE("-s", runtime_seconds_);

    // Set number of memory copy threads.
    ARG_IVALUE("-m", memory_threads_);

    // Set number of memory invert threads.
    ARG_IVALUE("-i", invert_threads_);

    // Set number of check-only threads.
    ARG_IVALUE("-c", check_threads_);

    // Set number of cache line size datastructures.
    ARG_IVALUE("--cc_inc_count", cc_inc_count_);

    // Set number of cache line size datastructures
    ARG_IVALUE("--cc_line_count", cc_cacheline_count_);

    // Flag set when cache coherency tests need to be run
    ARG_KVALUE("--cc_test", cc_test_, 1);

    // Set number of CPU stress threads.
    ARG_IVALUE("-C", cpu_stress_threads_);

    // Set logfile name.
    ARG_SVALUE("-l", logfilename_);

    // Verbosity level.
    ARG_IVALUE("-v", verbosity_);

    // Set maximum number of errors to collect. Stop running after this many.
    ARG_IVALUE("--max_errors", max_errorcount_);

    // Set pattern block size.
    ARG_IVALUE("-p", page_length_);

    // Set pattern block size.
    ARG_IVALUE("--filesize", filesize);

    // NUMA options.
    ARG_KVALUE("--local_numa", region_mode_, kLocalNuma);
    ARG_KVALUE("--remote_numa", region_mode_, kRemoteNuma);

    // Autodetect tempfile locations.
    ARG_KVALUE("--findfiles", findfiles_, 1);

    // Inject errors to force miscompare code paths
    ARG_KVALUE("--force_errors", error_injection_, true);
    ARG_KVALUE("--force_errors_like_crazy", crazy_error_injection_, true);
    if (crazy_error_injection_)
      error_injection_ = true;

    // Stop immediately on any arror, for debugging HW problems.
    ARG_KVALUE("--stop_on_errors", stop_on_error_, 1);

    // Don't use internal error polling, allow external detection.
    ARG_KVALUE("--no_errors", error_poll_, 0);

    // Never check data as you go.
    ARG_KVALUE("-F", strict_, 0);

    // Warm the cpu as you go.
    ARG_KVALUE("-W", warm_, 1);

    // Allow runnign on unknown systems with base unimplemented OsLayer
    ARG_KVALUE("-A", run_on_anything_, 1);

    // Size of read blocks for disk test.
    ARG_IVALUE("--read-block-size", read_block_size_);

    // Size of write blocks for disk test.
    ARG_IVALUE("--write-block-size", write_block_size_);

    // Size of segment for disk test.
    ARG_IVALUE("--segment-size", segment_size_);

    // Size of disk cache size for disk test.
    ARG_IVALUE("--cache-size", cache_size_);

    // Number of blocks to test per segment.
    ARG_IVALUE("--blocks-per-segment", blocks_per_segment_);

    // Maximum time a block read should take before warning.
    ARG_IVALUE("--read-threshold", read_threshold_);

    // Maximum time a block write should take before warning.
    ARG_IVALUE("--write-threshold", write_threshold_);

    // Do not write anything to disk in the disk test.
    ARG_KVALUE("--destructive", non_destructive_, 0);

    // Run SAT in monitor mode. No test load at all.
    ARG_KVALUE("--monitor_mode", monitor_mode_, true);

    // Run SAT in address mode. Tag all cachelines by virt addr.
    ARG_KVALUE("--tag_mode", tag_mode_, true);

    // Dump range map of tested pages..
    ARG_KVALUE("--do_page_map", do_page_map_, true);

    // Specify the physical address base to test.
    ARG_IVALUE("--paddr_base", paddr_base_);

    // Specify the frequency for power spikes.
    ARG_IVALUE("--pause_delay", pause_delay_);

    // Specify the duration of each pause (for power spikes).
    ARG_IVALUE("--pause_duration", pause_duration_);

    // Disk device names
    if (!strcmp(argv[i], "-d")) {
      i++;
      if (i < argc) {
        disk_threads_++;
        diskfilename_.push_back(string(argv[i]));
        blocktables_.push_back(new DiskBlockTable());
      }
      continue;
    }

    // Set number of disk random threads for each disk write thread.
    ARG_IVALUE("--random-threads", random_threads_);

    // Set a tempfile to use in a file thread.
    if (!strcmp(argv[i], "-f")) {
      i++;
      if (i < argc) {
        file_threads_++;
        filename_.push_back(string(argv[i]));
      }
      continue;
    }

    // Set a hostname to use in a network thread.
    if (!strcmp(argv[i], "-n")) {
      i++;
      if (i < argc) {
        net_threads_++;
        ipaddrs_.push_back(string(argv[i]));
      }
      continue;
    }

    // Run threads that listen for incoming SAT net connections.
    ARG_KVALUE("--listen", listen_threads_, 1);

    if (CheckGoogleSpecificArgs(argc, argv, &i)) {
      continue;
    }

    // Default:
    PrintVersion();
    PrintHelp();
    if (strcmp(argv[i], "-h") && strcmp(argv[i], "--help")) {
      printf("\n Unknown argument %s\n", argv[i]);
      bad_status();
      exit(1);
    }
    // Forget it, we printed the help, just bail.
    // We don't want to print test status, or any log parser stuff.
    exit(0);
  }

  Logger::GlobalLogger()->SetVerbosity(verbosity_);

  // Update relevant data members with parsed input.
  // Translate MB into bytes.
  size_ = static_cast<int64>(size_mb_) * kMegabyte;

  // Set logfile flag.
  if (strcmp(logfilename_, ""))
    use_logfile_ = 1;
  // Checks valid page length.
  if (page_length_ &&
      !(page_length_ & (page_length_ - 1)) &&
      (page_length_ > 1023)) {
    // Prints if we have changed from default.
    if (page_length_ != kSatPageSize)
      logprintf(12, "Log: Updating page size to %d\n", page_length_);
  } else {
    // Revert to default page length.
    logprintf(6, "Process Error: "
              "Invalid page size %d\n", page_length_);
    page_length_ = kSatPageSize;
    return false;
  }

  // Set disk_pages_ if filesize or page size changed.
  if (filesize != static_cast<uint64>(page_length_) *
                  static_cast<uint64>(disk_pages_)) {
    disk_pages_ = filesize / page_length_;
    if (disk_pages_ == 0)
      disk_pages_ = 1;
  }

  // Print each argument.
  for (int i = 0; i < argc; i++) {
    if (i)
      cmdline_ += " ";
    cmdline_ += argv[i];
  }

  return true;
}

void Sat::PrintHelp() {
  printf("Usage: ./sat(32|64) [options]\n"
         " -M mbytes        megabytes of ram to test\n"
         " -H mbytes        minimum megabytes of hugepages to require\n"
         " -s seconds       number of seconds to run\n"
         " -m threads       number of memory copy threads to run\n"
         " -i threads       number of memory invert threads to run\n"
         " -C threads       number of memory CPU stress threads to run\n"
         " --findfiles      find locations to do disk IO automatically\n"
         " -d device        add a direct write disk thread with block "
         "device (or file) 'device'\n"
         " -f filename      add a disk thread with "
         "tempfile 'filename'\n"
         " -l logfile       log output to file 'logfile'\n"
         " --max_errors n   exit early after finding 'n' errors\n"
         " -v level         verbosity (0-20), default is 8\n"
         " -W               Use more CPU-stressful memory copy\n"
         " -A               run in degraded mode on incompatible systems\n"
         " -p pagesize      size in bytes of memory chunks\n"
         " --filesize size  size of disk IO tempfiles\n"
         " -n ipaddr        add a network thread connecting to "
         "system at 'ipaddr'\n"
         " --listen         run a thread to listen for and respond "
         "to network threads.\n"
         " --no_errors      run without checking for ECC or other errors\n"
         " --force_errors   inject false errors to test error handling\n"
         " --force_errors_like_crazy   inject a lot of false errors "
         "to test error handling\n"
         " -F               don't result check each transaction\n"
         " --stop_on_errors  Stop after finding the first error.\n"
         " --read-block-size     size of block for reading (-d)\n"
         " --write-block-size    size of block for writing (-d). If not "
         "defined, the size of block for writing will be defined as the "
         "size of block for reading\n"
         " --segment-size   size of segments to split disk into (-d)\n"
         " --cache-size     size of disk cache (-d)\n"
         " --blocks-per-segment  number of blocks to read/write per "
         "segment per iteration (-d)\n"
         " --read-threshold      maximum time (in us) a block read should "
         "take (-d)\n"
         " --write-threshold     maximum time (in us) a block write "
         "should take (-d)\n"
         " --random-threads      number of random threads for each disk "
         "write thread (-d)\n"
         " --destructive    write/wipe disk partition (-d)\n"
         " --monitor_mode   only do ECC error polling, no stress load.\n"
         " --cc_test        do the cache coherency testing\n"
         " --cc_inc_count   number of times to increment the "
         "cacheline's member\n"
         " --cc_line_count  number of cache line sized datastructures "
         "to allocate for the cache coherency threads to operate\n"
         " --paddr_base     allocate memory starting from this address\n"
         " --pause_delay    delay (in seconds) between power spikes\n"
         " --pause_duration duration (in seconds) of each pause\n"
         " --local_numa : choose memory regions associated with "
         "each CPU to be tested by that CPU\n"
         " --remote_numa : choose memory regions not associated with "
         "each CPU to be tested by that CPU\n");
}

bool Sat::CheckGoogleSpecificArgs(int argc, char **argv, int *i) {
  // Do nothing, no google-specific argument on public stressapptest
  return false;
}

void Sat::GoogleOsOptions(std::map<std::string, std::string> *options) {
  // Do nothing, no OS-specific argument on public stressapptest
}

// Launch the SAT task threads. Returns 0 on error.
void Sat::InitializeThreads() {
  // Memory copy threads.
  AcquireWorkerLock();

  logprintf(12, "Log: Starting worker threads\n");
  WorkerVector *memory_vector = new WorkerVector();

  // Error polling thread.
  // This may detect ECC corrected errors, disk problems, or
  // any other errors normally hidden from userspace.
  WorkerVector *error_vector = new WorkerVector();
  if (error_poll_) {
    ErrorPollThread *thread = new ErrorPollThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &continuous_status_);

    error_vector->insert(error_vector->end(), thread);
  } else {
    logprintf(5, "Log: Skipping error poll thread due to --no_errors flag\n");
  }
  workers_map_.insert(make_pair(kErrorType, error_vector));

  // Only start error poll threads for monitor-mode SAT,
  // skip all other types of worker threads.
  if (monitor_mode_) {
    ReleaseWorkerLock();
    return;
  }

  for (int i = 0; i < memory_threads_; i++) {
    CopyThread *thread = new CopyThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &power_spike_status_);

    if ((region_count_ > 1) && (region_mode_)) {
      int32 region = region_find(i % region_count_);
      cpu_set_t *cpuset = os_->FindCoreMask(region);
      sat_assert(cpuset);
      if (region_mode_ == kLocalNuma) {
        // Choose regions associated with this CPU.
        thread->set_cpu_mask(cpuset);
        thread->set_tag(1 << region);
      } else if (region_mode_ == kRemoteNuma) {
        // Choose regions not associated with this CPU..
        thread->set_cpu_mask(cpuset);
        thread->set_tag(region_mask_ & ~(1 << region));
      }
    } else {
      cpu_set_t available_cpus;
      thread->AvailableCpus(&available_cpus);
      int cores = cpuset_count(&available_cpus);
      // Don't restrict thread location if we have more than one
      // thread per core. Not so good for performance.
      if (cpu_stress_threads_ + memory_threads_ <= cores) {
        // Place a thread on alternating cores first.
        // This assures interleaved core use with no overlap.
        int nthcore = i;
        int nthbit = (((2 * nthcore) % cores) +
                      (((2 * nthcore) / cores) % 2)) % cores;
        cpu_set_t all_cores;
        cpuset_set_ab(&all_cores, 0, cores);
        if (!cpuset_isequal(&available_cpus, &all_cores)) {
          // We are assuming the bits are contiguous.
          // Complain if this is not so.
          logprintf(0, "Log: cores = %s, expected %s\n",
                    cpuset_format(&available_cpus).c_str(),
                    cpuset_format(&all_cores).c_str());
        }

        // Set thread affinity.
        thread->set_cpu_mask_to_cpu(nthbit);
      }
    }
    memory_vector->insert(memory_vector->end(), thread);
  }
  workers_map_.insert(make_pair(kMemoryType, memory_vector));

  // File IO threads.
  WorkerVector *fileio_vector = new WorkerVector();
  for (int i = 0; i < file_threads_; i++) {
    FileThread *thread = new FileThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &power_spike_status_);
    thread->SetFile(filename_[i].c_str());
    // Set disk threads high priority. They don't take much processor time,
    // but blocking them will delay disk IO.
    thread->SetPriority(WorkerThread::High);

    fileio_vector->insert(fileio_vector->end(), thread);
  }
  workers_map_.insert(make_pair(kFileIOType, fileio_vector));

  // Net IO threads.
  WorkerVector *netio_vector = new WorkerVector();
  WorkerVector *netslave_vector = new WorkerVector();
  if (listen_threads_ > 0) {
    // Create a network slave thread. This listens for connections.
    NetworkListenThread *thread = new NetworkListenThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &continuous_status_);

    netslave_vector->insert(netslave_vector->end(), thread);
  }
  for (int i = 0; i < net_threads_; i++) {
    NetworkThread *thread = new NetworkThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &continuous_status_);
    thread->SetIP(ipaddrs_[i].c_str());

    netio_vector->insert(netio_vector->end(), thread);
  }
  workers_map_.insert(make_pair(kNetIOType, netio_vector));
  workers_map_.insert(make_pair(kNetSlaveType, netslave_vector));

  // Result check threads.
  WorkerVector *check_vector = new WorkerVector();
  for (int i = 0; i < check_threads_; i++) {
    CheckThread *thread = new CheckThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &continuous_status_);

    check_vector->insert(check_vector->end(), thread);
  }
  workers_map_.insert(make_pair(kCheckType, check_vector));

  // Memory invert threads.
  logprintf(12, "Log: Starting invert threads\n");
  WorkerVector *invert_vector = new WorkerVector();
  for (int i = 0; i < invert_threads_; i++) {
    InvertThread *thread = new InvertThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &continuous_status_);

    invert_vector->insert(invert_vector->end(), thread);
  }
  workers_map_.insert(make_pair(kInvertType, invert_vector));

  // Disk stress threads.
  WorkerVector *disk_vector = new WorkerVector();
  WorkerVector *random_vector = new WorkerVector();
  logprintf(12, "Log: Starting disk stress threads\n");
  for (int i = 0; i < disk_threads_; i++) {
    // Creating write threads
    DiskThread *thread = new DiskThread(blocktables_[i]);
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &power_spike_status_);
    thread->SetDevice(diskfilename_[i].c_str());
    if (thread->SetParameters(read_block_size_, write_block_size_,
                              segment_size_, cache_size_,
                              blocks_per_segment_,
                              read_threshold_, write_threshold_,
                              non_destructive_)) {
      disk_vector->insert(disk_vector->end(), thread);
    } else {
      logprintf(12, "Log: DiskThread::SetParameters() failed\n");
      delete thread;
    }

    for (int j = 0; j < random_threads_; j++) {
      // Creating random threads
      RandomDiskThread *rthread = new RandomDiskThread(blocktables_[i]);
      rthread->InitThread(total_threads_++, this, os_, patternlist_,
                          &power_spike_status_);
      rthread->SetDevice(diskfilename_[i].c_str());
      if (rthread->SetParameters(read_block_size_, write_block_size_,
                                 segment_size_, cache_size_,
                                 blocks_per_segment_,
                                 read_threshold_, write_threshold_,
                                 non_destructive_)) {
        random_vector->insert(random_vector->end(), rthread);
      } else {
      logprintf(12, "Log: RandomDiskThread::SetParameters() failed\n");
        delete rthread;
      }
    }
  }

  workers_map_.insert(make_pair(kDiskType, disk_vector));
  workers_map_.insert(make_pair(kRandomDiskType, random_vector));

  // CPU stress threads.
  WorkerVector *cpu_vector = new WorkerVector();
  logprintf(12, "Log: Starting cpu stress threads\n");
  for (int i = 0; i < cpu_stress_threads_; i++) {
    CpuStressThread *thread = new CpuStressThread();
    thread->InitThread(total_threads_++, this, os_, patternlist_,
                       &continuous_status_);

    // Don't restrict thread location if we have more than one
    // thread per core. Not so good for performance.
    cpu_set_t available_cpus;
    thread->AvailableCpus(&available_cpus);
    int cores = cpuset_count(&available_cpus);
    if (cpu_stress_threads_ + memory_threads_ <= cores) {
      // Place a thread on alternating cores first.
      // Go in reverse order for CPU stress threads. This assures interleaved
      // core use with no overlap.
      int nthcore = (cores - 1) - i;
      int nthbit = (((2 * nthcore) % cores) +
                    (((2 * nthcore) / cores) % 2)) % cores;
      cpu_set_t all_cores;
      cpuset_set_ab(&all_cores, 0, cores);
      if (!cpuset_isequal(&available_cpus, &all_cores)) {
        logprintf(0, "Log: cores = %s, expected %s\n",
                  cpuset_format(&available_cpus).c_str(),
                  cpuset_format(&all_cores).c_str());
      }

      // Set thread affinity.
      thread->set_cpu_mask_to_cpu(nthbit);
    }


    cpu_vector->insert(cpu_vector->end(), thread);
  }
  workers_map_.insert(make_pair(kCPUType, cpu_vector));

  // CPU Cache Coherency Threads - one for each core available.
  if (cc_test_) {
    WorkerVector *cc_vector = new WorkerVector();
    logprintf(12, "Log: Starting cpu cache coherency threads\n");

    // Allocate the shared datastructure to be worked on by the threads.
    cc_cacheline_data_ = reinterpret_cast<cc_cacheline_data*>(
        malloc(sizeof(cc_cacheline_data) * cc_cacheline_count_));
    sat_assert(cc_cacheline_data_ != NULL);

    // Initialize the strucutre.
    memset(cc_cacheline_data_, 0,
           sizeof(cc_cacheline_data) * cc_cacheline_count_);

    int num_cpus = CpuCount();
    // Allocate all the nums once so that we get a single chunk
    // of contiguous memory.
    int *num;
#ifdef HAVE_POSIX_MEMALIGN
    int err_result = posix_memalign(
        reinterpret_cast<void**>(&num),
        kCacheLineSize, sizeof(*num) * num_cpus * cc_cacheline_count_);
#else
    num = reinterpret_cast<int*>(memalign(kCacheLineSize,
			sizeof(*num) * num_cpus * cc_cacheline_count_));
    int err_result = (num == 0);
#endif
    sat_assert(err_result == 0);

    int cline;
    for (cline = 0; cline < cc_cacheline_count_; cline++) {
      memset(num, 0, sizeof(num_cpus) * num_cpus);
      cc_cacheline_data_[cline].num = num;
      num += num_cpus;
    }

    int tnum;
    for (tnum = 0; tnum < num_cpus; tnum++) {
      CpuCacheCoherencyThread *thread =
          new CpuCacheCoherencyThread(cc_cacheline_data_, cc_cacheline_count_,
                                      tnum, cc_inc_count_);
      thread->InitThread(total_threads_++, this, os_, patternlist_,
                         &continuous_status_);
      // Pin the thread to a particular core.
      thread->set_cpu_mask_to_cpu(tnum);

      // Insert the thread into the vector.
      cc_vector->insert(cc_vector->end(), thread);
    }
    workers_map_.insert(make_pair(kCCType, cc_vector));
  }
  ReleaseWorkerLock();
}

// Return the number of cpus actually present in the machine.
int Sat::CpuCount() {
  return sysconf(_SC_NPROCESSORS_CONF);
}

// Notify and reap worker threads.
void Sat::JoinThreads() {
  logprintf(12, "Log: Joining worker threads\n");
  power_spike_status_.StopWorkers();
  continuous_status_.StopWorkers();

  AcquireWorkerLock();
  for (WorkerMap::const_iterator map_it = workers_map_.begin();
       map_it != workers_map_.end(); ++map_it) {
    for (WorkerVector::const_iterator it = map_it->second->begin();
         it != map_it->second->end(); ++it) {
      logprintf(12, "Log: Joining thread %d\n", (*it)->ThreadID());
      (*it)->JoinThread();
    }
  }
  ReleaseWorkerLock();

  QueueStats();

  // Finish up result checking.
  // Spawn 4 check threads to minimize check time.
  logprintf(12, "Log: Finished countdown, begin to result check\n");
  WorkerStatus reap_check_status;
  WorkerVector reap_check_vector;

  // No need for check threads for monitor mode.
  if (!monitor_mode_) {
    // Initialize the check threads.
    for (int i = 0; i < fill_threads_; i++) {
      CheckThread *thread = new CheckThread();
      thread->InitThread(total_threads_++, this, os_, patternlist_,
                         &reap_check_status);
      logprintf(12, "Log: Finished countdown, begin to result check\n");
      reap_check_vector.push_back(thread);
    }
  }

  reap_check_status.Initialize();
  // Check threads should be marked to stop ASAP.
  reap_check_status.StopWorkers();

  // Spawn the check threads.
  for (WorkerVector::const_iterator it = reap_check_vector.begin();
       it != reap_check_vector.end(); ++it) {
    logprintf(12, "Log: Spawning thread %d\n", (*it)->ThreadID());
    (*it)->SpawnThread();
  }

  // Join the check threads.
  for (WorkerVector::const_iterator it = reap_check_vector.begin();
       it != reap_check_vector.end(); ++it) {
    logprintf(12, "Log: Joining thread %d\n", (*it)->ThreadID());
    (*it)->JoinThread();
  }

  // Reap all children. Stopped threads should have already ended.
  // Result checking threads will end when they have finished
  // result checking.
  logprintf(12, "Log: Join all outstanding threads\n");

  // Find all errors.
  errorcount_ = GetTotalErrorCount();

  AcquireWorkerLock();
  for (WorkerMap::const_iterator map_it = workers_map_.begin();
       map_it != workers_map_.end(); ++map_it) {
    for (WorkerVector::const_iterator it = map_it->second->begin();
         it != map_it->second->end(); ++it) {
      logprintf(12, "Log: Reaping thread status %d\n", (*it)->ThreadID());
      if ((*it)->GetStatus() != 1) {
        logprintf(0, "Process Error: Thread %d failed with status %d at "
                  "%.2f seconds\n",
                  (*it)->ThreadID(), (*it)->GetStatus(),
                  (*it)->GetRunDurationUSec()*1.0/1000000);
        bad_status();
      }
      int priority = 12;
      if ((*it)->GetErrorCount())
        priority = 5;
      logprintf(priority, "Log: Thread %d found %lld hardware incidents\n",
                (*it)->ThreadID(), (*it)->GetErrorCount());
    }
  }
  ReleaseWorkerLock();


  // Add in any errors from check threads.
  for (WorkerVector::const_iterator it = reap_check_vector.begin();
       it != reap_check_vector.end(); ++it) {
    logprintf(12, "Log: Reaping thread status %d\n", (*it)->ThreadID());
    if ((*it)->GetStatus() != 1) {
      logprintf(0, "Process Error: Thread %d failed with status %d at "
                "%.2f seconds\n",
                (*it)->ThreadID(), (*it)->GetStatus(),
                (*it)->GetRunDurationUSec()*1.0/1000000);
      bad_status();
    }
    errorcount_ += (*it)->GetErrorCount();
    int priority = 12;
    if ((*it)->GetErrorCount())
      priority = 5;
    logprintf(priority, "Log: Thread %d found %lld hardware incidents\n",
              (*it)->ThreadID(), (*it)->GetErrorCount());
    delete (*it);
  }
  reap_check_vector.clear();
  reap_check_status.Destroy();
}

// Print queuing information.
void Sat::QueueStats() {
  finelock_q_->QueueAnalysis();
}

void Sat::AnalysisAllStats() {
  float max_runtime_sec = 0.;
  float total_data = 0.;
  float total_bandwidth = 0.;
  float thread_runtime_sec = 0.;

  for (WorkerMap::const_iterator map_it = workers_map_.begin();
       map_it != workers_map_.end(); ++map_it) {
    for (WorkerVector::const_iterator it = map_it->second->begin();
         it != map_it->second->end(); ++it) {
      thread_runtime_sec = (*it)->GetRunDurationUSec()*1.0/1000000;
      total_data += (*it)->GetMemoryCopiedData();
      total_data += (*it)->GetDeviceCopiedData();
      if (thread_runtime_sec > max_runtime_sec) {
        max_runtime_sec = thread_runtime_sec;
      }
    }
  }

  total_bandwidth = total_data / max_runtime_sec;

  logprintf(0, "Stats: Completed: %.2fM in %.2fs %.2fMB/s, "
            "with %d hardware incidents, %d errors\n",
            total_data,
            max_runtime_sec,
            total_bandwidth,
            errorcount_,
            statuscount_);
}

void Sat::MemoryStats() {
  float memcopy_data = 0.;
  float memcopy_bandwidth = 0.;
  WorkerMap::const_iterator mem_it = workers_map_.find(
      static_cast<int>(kMemoryType));
  WorkerMap::const_iterator file_it = workers_map_.find(
      static_cast<int>(kFileIOType));
  sat_assert(mem_it != workers_map_.end());
  sat_assert(file_it != workers_map_.end());
  for (WorkerVector::const_iterator it = mem_it->second->begin();
       it != mem_it->second->end(); ++it) {
    memcopy_data += (*it)->GetMemoryCopiedData();
    memcopy_bandwidth += (*it)->GetMemoryBandwidth();
  }
  for (WorkerVector::const_iterator it = file_it->second->begin();
       it != file_it->second->end(); ++it) {
    memcopy_data += (*it)->GetMemoryCopiedData();
    memcopy_bandwidth += (*it)->GetMemoryBandwidth();
  }
  GoogleMemoryStats(&memcopy_data, &memcopy_bandwidth);
  logprintf(4, "Stats: Memory Copy: %.2fM at %.2fMB/s\n",
            memcopy_data,
            memcopy_bandwidth);
}

void Sat::GoogleMemoryStats(float *memcopy_data,
                            float *memcopy_bandwidth) {
  // Do nothing, should be implemented by subclasses.
}

void Sat::FileStats() {
  float file_data = 0.;
  float file_bandwidth = 0.;
  WorkerMap::const_iterator file_it = workers_map_.find(
      static_cast<int>(kFileIOType));
  sat_assert(file_it != workers_map_.end());
  for (WorkerVector::const_iterator it = file_it->second->begin();
       it != file_it->second->end(); ++it) {
    file_data += (*it)->GetDeviceCopiedData();
    file_bandwidth += (*it)->GetDeviceBandwidth();
  }
  logprintf(4, "Stats: File Copy: %.2fM at %.2fMB/s\n",
            file_data,
            file_bandwidth);
}

void Sat::CheckStats() {
  float check_data = 0.;
  float check_bandwidth = 0.;
  WorkerMap::const_iterator check_it = workers_map_.find(
      static_cast<int>(kCheckType));
  sat_assert(check_it != workers_map_.end());
  for (WorkerVector::const_iterator it = check_it->second->begin();
       it != check_it->second->end(); ++it) {
    check_data += (*it)->GetMemoryCopiedData();
    check_bandwidth += (*it)->GetMemoryBandwidth();
  }
  logprintf(4, "Stats: Data Check: %.2fM at %.2fMB/s\n",
            check_data,
            check_bandwidth);
}

void Sat::NetStats() {
  float net_data = 0.;
  float net_bandwidth = 0.;
  WorkerMap::const_iterator netio_it = workers_map_.find(
      static_cast<int>(kNetIOType));
  WorkerMap::const_iterator netslave_it = workers_map_.find(
      static_cast<int>(kNetSlaveType));
  sat_assert(netio_it != workers_map_.end());
  sat_assert(netslave_it != workers_map_.end());
  for (WorkerVector::const_iterator it = netio_it->second->begin();
       it != netio_it->second->end(); ++it) {
    net_data += (*it)->GetDeviceCopiedData();
    net_bandwidth += (*it)->GetDeviceBandwidth();
  }
  for (WorkerVector::const_iterator it = netslave_it->second->begin();
       it != netslave_it->second->end(); ++it) {
    net_data += (*it)->GetDeviceCopiedData();
    net_bandwidth += (*it)->GetDeviceBandwidth();
  }
  logprintf(4, "Stats: Net Copy: %.2fM at %.2fMB/s\n",
            net_data,
            net_bandwidth);
}

void Sat::InvertStats() {
  float invert_data = 0.;
  float invert_bandwidth = 0.;
  WorkerMap::const_iterator invert_it = workers_map_.find(
      static_cast<int>(kInvertType));
  sat_assert(invert_it != workers_map_.end());
  for (WorkerVector::const_iterator it = invert_it->second->begin();
       it != invert_it->second->end(); ++it) {
    invert_data += (*it)->GetMemoryCopiedData();
    invert_bandwidth += (*it)->GetMemoryBandwidth();
  }
  logprintf(4, "Stats: Invert Data: %.2fM at %.2fMB/s\n",
            invert_data,
            invert_bandwidth);
}

void Sat::DiskStats() {
  float disk_data = 0.;
  float disk_bandwidth = 0.;
  WorkerMap::const_iterator disk_it = workers_map_.find(
      static_cast<int>(kDiskType));
  WorkerMap::const_iterator random_it = workers_map_.find(
      static_cast<int>(kRandomDiskType));
  sat_assert(disk_it != workers_map_.end());
  sat_assert(random_it != workers_map_.end());
  for (WorkerVector::const_iterator it = disk_it->second->begin();
       it != disk_it->second->end(); ++it) {
    disk_data += (*it)->GetDeviceCopiedData();
    disk_bandwidth += (*it)->GetDeviceBandwidth();
  }
  for (WorkerVector::const_iterator it = random_it->second->begin();
       it != random_it->second->end(); ++it) {
    disk_data += (*it)->GetDeviceCopiedData();
    disk_bandwidth += (*it)->GetDeviceBandwidth();
  }

  logprintf(4, "Stats: Disk: %.2fM at %.2fMB/s\n",
            disk_data,
            disk_bandwidth);
}

// Process worker thread data for bandwidth information, and error results.
// You can add more methods here just subclassing SAT.
void Sat::RunAnalysis() {
  AnalysisAllStats();
  MemoryStats();
  FileStats();
  NetStats();
  CheckStats();
  InvertStats();
  DiskStats();
}

// Get total error count, summing across all threads..
int64 Sat::GetTotalErrorCount() {
  int64 errors = 0;

  AcquireWorkerLock();
  for (WorkerMap::const_iterator map_it = workers_map_.begin();
       map_it != workers_map_.end(); ++map_it) {
    for (WorkerVector::const_iterator it = map_it->second->begin();
         it != map_it->second->end(); ++it) {
      errors += (*it)->GetErrorCount();
    }
  }
  ReleaseWorkerLock();
  return errors;
}


void Sat::SpawnThreads() {
  logprintf(12, "Log: Initializing WorkerStatus objects\n");
  power_spike_status_.Initialize();
  continuous_status_.Initialize();
  logprintf(12, "Log: Spawning worker threads\n");
  for (WorkerMap::const_iterator map_it = workers_map_.begin();
       map_it != workers_map_.end(); ++map_it) {
    for (WorkerVector::const_iterator it = map_it->second->begin();
         it != map_it->second->end(); ++it) {
      logprintf(12, "Log: Spawning thread %d\n", (*it)->ThreadID());
      (*it)->SpawnThread();
    }
  }
}

// Delete used worker thread objects.
void Sat::DeleteThreads() {
  logprintf(12, "Log: Deleting worker threads\n");
  for (WorkerMap::const_iterator map_it = workers_map_.begin();
       map_it != workers_map_.end(); ++map_it) {
    for (WorkerVector::const_iterator it = map_it->second->begin();
         it != map_it->second->end(); ++it) {
      logprintf(12, "Log: Deleting thread %d\n", (*it)->ThreadID());
      delete (*it);
    }
    delete map_it->second;
  }
  workers_map_.clear();
  logprintf(12, "Log: Destroying WorkerStatus objects\n");
  power_spike_status_.Destroy();
  continuous_status_.Destroy();
}

namespace {
// Calculates the next time an action in Sat::Run() should occur, based on a
// schedule derived from a start point and a regular frequency.
//
// Using frequencies instead of intervals with their accompanying drift allows
// users to better predict when the actions will occur throughout a run.
//
// Arguments:
//   frequency: seconds
//   start: unixtime
//   now: unixtime
//
// Returns: unixtime
inline time_t NextOccurance(time_t frequency, time_t start, time_t now) {
  return start + frequency + (((now - start) / frequency) * frequency);
}
}

// Run the actual test.
bool Sat::Run() {
  // Install signal handlers to gracefully exit in the middle of a run.
  //
  // Why go through this whole rigmarole?  It's the only standards-compliant
  // (C++ and POSIX) way to handle signals in a multithreaded program.
  // Specifically:
  //
  // 1) (C++) The value of a variable not of type "volatile sig_atomic_t" is
  //    unspecified upon entering a signal handler and, if modified by the
  //    handler, is unspecified after leaving the handler.
  //
  // 2) (POSIX) After the value of a variable is changed in one thread, another
  //    thread is only guaranteed to see the new value after both threads have
  //    acquired or released the same mutex or rwlock, synchronized to the
  //    same barrier, or similar.
  //
  // #1 prevents the use of #2 in a signal handler, so the signal handler must
  // be called in the same thread that reads the "volatile sig_atomic_t"
  // variable it sets.  We enforce that by blocking the signals in question in
  // the worker threads, forcing them to be handled by this thread.
  logprintf(12, "Log: Installing signal handlers\n");
  sigset_t new_blocked_signals;
  sigemptyset(&new_blocked_signals);
  sigaddset(&new_blocked_signals, SIGINT);
  sigaddset(&new_blocked_signals, SIGTERM);
  sigset_t prev_blocked_signals;
  pthread_sigmask(SIG_BLOCK, &new_blocked_signals, &prev_blocked_signals);
  sighandler_t prev_sigint_handler = signal(SIGINT, SatHandleBreak);
  sighandler_t prev_sigterm_handler = signal(SIGTERM, SatHandleBreak);

  // Kick off all the worker threads.
  logprintf(12, "Log: Launching worker threads\n");
  InitializeThreads();
  SpawnThreads();
  pthread_sigmask(SIG_SETMASK, &prev_blocked_signals, NULL);

  logprintf(12, "Log: Starting countdown with %d seconds\n", runtime_seconds_);

  // In seconds.
  static const time_t kSleepFrequency = 5;
  // All of these are in seconds.  You probably want them to be >=
  // kSleepFrequency and multiples of kSleepFrequency, but neither is necessary.
  static const time_t kInjectionFrequency = 10;
  static const time_t kPrintFrequency = 10;

  const time_t start = time(NULL);
  const time_t end = start + runtime_seconds_;
  time_t now = start;
  time_t next_print = start + kPrintFrequency;
  time_t next_pause = start + pause_delay_;
  time_t next_resume = 0;
  time_t next_injection;
  if (crazy_error_injection_) {
    next_injection = start + kInjectionFrequency;
  } else {
    next_injection = 0;
  }

  while (now < end) {
    // This is an int because it's for logprintf().
    const int seconds_remaining = end - now;

    if (user_break_) {
      // Handle early exit.
      logprintf(0, "Log: User exiting early (%d seconds remaining)\n",
                seconds_remaining);
      break;
    }

    // If we have an error limit, check it here and see if we should exit.
    if (max_errorcount_ != 0) {
      uint64 errors = GetTotalErrorCount();
      if (errors > max_errorcount_) {
        logprintf(0, "Log: Exiting early (%d seconds remaining) "
                     "due to excessive failures (%lld)\n",
                  seconds_remaining,
                  errors);
        break;
      }
    }

    if (now >= next_print) {
      // Print a count down message.
      logprintf(5, "Log: Seconds remaining: %d\n", seconds_remaining);
      next_print = NextOccurance(kPrintFrequency, start, now);
    }

    if (next_injection && now >= next_injection) {
      // Inject an error.
      logprintf(4, "Log: Injecting error (%d seconds remaining)\n",
                seconds_remaining);
      struct page_entry src;
      GetValid(&src);
      src.pattern = patternlist_->GetPattern(0);
      PutValid(&src);
      next_injection = NextOccurance(kInjectionFrequency, start, now);
    }

    if (next_pause && now >= next_pause) {
      // Tell worker threads to pause in preparation for a power spike.
      logprintf(4, "Log: Pausing worker threads in preparation for power spike "
                "(%d seconds remaining)\n", seconds_remaining);
      power_spike_status_.PauseWorkers();
      logprintf(12, "Log: Worker threads paused\n");
      next_pause = 0;
      next_resume = now + pause_duration_;
    }

    if (next_resume && now >= next_resume) {
      // Tell worker threads to resume in order to cause a power spike.
      logprintf(4, "Log: Resuming worker threads to cause a power spike (%d "
                "seconds remaining)\n", seconds_remaining);
      power_spike_status_.ResumeWorkers();
      logprintf(12, "Log: Worker threads resumed\n");
      next_pause = NextOccurance(pause_delay_, start, now);
      next_resume = 0;
    }

    sat_sleep(NextOccurance(kSleepFrequency, start, now) - now);
    now = time(NULL);
  }

  JoinThreads();

  logprintf(0, "Stats: Found %lld hardware incidents\n", errorcount_);

  if (!monitor_mode_)
    RunAnalysis();

  DeleteThreads();

  logprintf(12, "Log: Uninstalling signal handlers\n");
  signal(SIGINT, prev_sigint_handler);
  signal(SIGTERM, prev_sigterm_handler);

  return true;
}

// Clean up all resources.
bool Sat::Cleanup() {
  g_sat = NULL;
  Logger::GlobalLogger()->StopThread();
  Logger::GlobalLogger()->SetStdoutOnly();
  if (logfile_) {
    close(logfile_);
    logfile_ = 0;
  }
  if (patternlist_) {
    patternlist_->Destroy();
    delete patternlist_;
    patternlist_ = 0;
  }
  if (os_) {
    os_->FreeTestMem();
    delete os_;
    os_ = 0;
  }
  if (empty_) {
    delete empty_;
    empty_ = 0;
  }
  if (valid_) {
    delete valid_;
    valid_ = 0;
  }
  if (finelock_q_) {
    delete finelock_q_;
    finelock_q_ = 0;
  }
  if (page_bitmap_) {
    delete[] page_bitmap_;
  }

  for (size_t i = 0; i < blocktables_.size(); i++) {
    delete blocktables_[i];
  }

  if (cc_cacheline_data_) {
    // The num integer arrays for all the cacheline structures are
    // allocated as a single chunk. The pointers in the cacheline struct
    // are populated accordingly. Hence calling free on the first
    // cacheline's num's address is going to free the entire array.
    // TODO(aganti): Refactor this to have a class for the cacheline
    // structure (currently defined in worker.h) and clean this up
    // in the destructor of that class.
    if (cc_cacheline_data_[0].num) {
      free(cc_cacheline_data_[0].num);
    }
    free(cc_cacheline_data_);
  }

  sat_assert(0 == pthread_mutex_destroy(&worker_lock_));

  return true;
}


// Pretty print really obvious results.
bool Sat::PrintResults() {
  bool result = true;

  logprintf(4, "\n");
  if (statuscount_) {
    logprintf(4, "Status: FAIL - test encountered procedural errors\n");
    result = false;
  } else if (errorcount_) {
    logprintf(4, "Status: FAIL - test discovered HW problems\n");
    result = false;
  } else {
    logprintf(4, "Status: PASS - please verify no corrected errors\n");
  }
  logprintf(4, "\n");

  return result;
}

// Helper functions.
void Sat::AcquireWorkerLock() {
  sat_assert(0 == pthread_mutex_lock(&worker_lock_));
}
void Sat::ReleaseWorkerLock() {
  sat_assert(0 == pthread_mutex_unlock(&worker_lock_));
}

void logprintf(int priority, const char *format, ...) {
  va_list args;
  va_start(args, format);
  Logger::GlobalLogger()->VLogF(priority, format, args);
  va_end(args);
}
