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

// sat.h : sat stress test object interface and data structures

#ifndef STRESSAPPTEST_SAT_H_
#define STRESSAPPTEST_SAT_H_

#include <signal.h>

#include <map>
#include <string>
#include <vector>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "finelock_queue.h"
#include "queue.h"
#include "sattypes.h"
#include "worker.h"
#include "os.h"

// SAT stress test class.
class Sat {
 public:
  // Enum for page queue implementation switch.
  enum PageQueueType { SAT_ONELOCK, SAT_FINELOCK };

  Sat();
  virtual ~Sat();

  // Read configuration from arguments. Called first.
  bool ParseArgs(int argc, char **argv);
  virtual bool CheckGoogleSpecificArgs(int argc, char **argv, int *i);
  // Initialize data structures, subclasses, and resources,
  // based on command line args.
  // Called after ParseArgs().
  bool Initialize();

  // Execute the test. Initialize() and ParseArgs() must be called first.
  // This must be called from a single-threaded program.
  bool Run();

  // Pretty print result summary.
  // Called after Run().
  // Return value is success or failure of the SAT run, *not* of this function!
  bool PrintResults();

  // Pretty print version info.
  bool PrintVersion();

  // Pretty print help.
  virtual void PrintHelp();

  // Clean up allocations and resources.
  // Called last.
  bool Cleanup();

  // Abort Run().  Only for use by Run()-installed signal handlers.
  void Break() { user_break_ = true; }

  // Fetch and return empty and full pages into the empty and full pools.
  bool GetValid(struct page_entry *pe);
  bool PutValid(struct page_entry *pe);
  bool GetEmpty(struct page_entry *pe);
  bool PutEmpty(struct page_entry *pe);

  bool GetValid(struct page_entry *pe, int32 tag);
  bool GetEmpty(struct page_entry *pe, int32 tag);

  // Accessor functions.
  int verbosity() const { return verbosity_; }
  int logfile() const { return logfile_; }
  int page_length() const { return page_length_; }
  int disk_pages() const { return disk_pages_; }
  int strict() const { return strict_; }
  int tag_mode() const { return tag_mode_; }
  int status() const { return statuscount_; }
  void bad_status() { statuscount_++; }
  int errors() const { return errorcount_; }
  int warm() const { return warm_; }
  bool stop_on_error() const { return stop_on_error_; }
  int32 region_mask() const { return region_mask_; }
  // Semi-accessor to find the "nth" region to avoid replicated bit searching..
  int32 region_find(int32 num) const {
    for (int i = 0; i < 32; i++) {
      if ((1 << i) & region_mask_) {
        if (num == 0)
          return i;
        num--;
      }
    }
    return 0;
  }

  // Causes false errors for unittesting.
  // Setting to "true" causes errors to be injected.
  void set_error_injection(bool errors) { error_injection_ = errors; }
  bool error_injection() const { return error_injection_; }

 protected:
  // Opens log file for writing. Returns 0 on failure.
  bool InitializeLogfile();
  // Checks for supported environment. Returns 0 on failure.
  bool CheckEnvironment();
  // Allocates size_ bytes of test memory.
  bool AllocateMemory();
  // Initializes datapattern reference structures.
  bool InitializePatterns();
  // Initializes test memory with datapatterns.
  bool InitializePages();

  // Start up worker threads.
  virtual void InitializeThreads();
  // Spawn worker threads.
  void SpawnThreads();
  // Reap worker threads.
  void JoinThreads();
  // Run bandwidth and error analysis.
  virtual void RunAnalysis();
  // Delete worker threads.
  void DeleteThreads();

  // Return the number of cpus in the system.
  int CpuCount();

  // Collect error counts from threads.
  int64 GetTotalErrorCount();

  // Command line arguments.
  string cmdline_;

  // Memory and test configuration.
  int runtime_seconds_;               // Seconds to run.
  int page_length_;                   // Length of each memory block.
  int64 pages_;                       // Number of memory blocks.
  int64 size_;                        // Size of memory tested, in bytes.
  int64 size_mb_;                     // Size of memory tested, in MB.
  int64 min_hugepages_mbytes_;        // Minimum hugepages size.
  int64 freepages_;                   // How many invalid pages we need.
  int disk_pages_;                    // Number of pages per temp file.
  uint64 paddr_base_;                 // Physical address base.

  // Control flags.
  volatile sig_atomic_t user_break_;  // User has signalled early exit.  Used as
                                      // a boolean.
  int verbosity_;                     // How much to print.
  int strict_;                        // Check results per transaction.
  int warm_;                          // FPU warms CPU while coying.
  int address_mode_;                  // 32 or 64 bit binary.
  bool stop_on_error_;                // Exit immendiately on any error.
  bool findfiles_;                    // Autodetect tempfile locations.

  bool error_injection_;              // Simulate errors, for unittests.
  bool crazy_error_injection_;        // Simulate lots of errors.
  uint64 max_errorcount_;             // Number of errors before forced exit.
  int run_on_anything_;               // Ignore unknown machine ereor.
  int use_logfile_;                   // Log to a file.
  char logfilename_[255];             // Name of file to log to.
  int logfile_;                       // File handle to log to.

  // Disk thread options.
  int read_block_size_;               // Size of block to read from disk.
  int write_block_size_;              // Size of block to write to disk.
  int64 segment_size_;                // Size of segment to split disk into.
  int cache_size_;                    // Size of disk cache.
  int blocks_per_segment_;            // Number of blocks to test per segment.
  int read_threshold_;                // Maximum time (in us) a read should take
                                      // before warning of a slow read.
  int write_threshold_;               // Maximum time (in us) a write should
                                      // take before warning of a slow write.
  int non_destructive_;               // Whether to use non-destructive mode for
                                      // the disk test.

  // Generic Options.
  int monitor_mode_;                  // Switch for monitor-only mode SAT.
                                      // This switch trumps most of the other
                                      // argument, as SAT will only run error
                                      // polling threads.
  int tag_mode_;                      // Do tagging of memory and strict
                                      // checking for misplaced cachelines.

  bool do_page_map_;                  // Should we print a list of used pages?
  unsigned char *page_bitmap_;        // Store bitmap of physical pages seen.
  uint64 page_bitmap_size_;           // Length of physical memory represented.

  // Cpu Cache Coherency Options.
  bool cc_test_;                      // Flag to decide whether to start the
                                      // cache coherency threads.
  int cc_cacheline_count_;            // Number of cache line size structures.
  int cc_inc_count_;                  // Number of times to increment the shared
                                      // cache lines structure members.

  // Thread control.
  int file_threads_;                  // Threads of file IO.
  int net_threads_;                   // Threads of network IO.
  int listen_threads_;                // Threads for network IO to connect.
  int memory_threads_;                // Threads of memcpy.
  int invert_threads_;                // Threads of invert.
  int fill_threads_;                  // Threads of memset.
  int check_threads_;                 // Threads of strcmp.
  int cpu_stress_threads_;            // Threads of CPU stress workload.
  int disk_threads_;                  // Threads of disk test.
  int random_threads_;                // Number of random disk threads.
  int total_threads_;                 // Total threads used.
  bool error_poll_;                   // Poll for system errors.

  // Resources.
  cc_cacheline_data *cc_cacheline_data_;  // The cache line sized datastructure
                                          // used by the ccache threads
                                          // (in worker.h).
  vector<string> filename_;           // Filenames for file IO.
  vector<string> ipaddrs_;            // Addresses for network IO.
  vector<string> diskfilename_;       // Filename for disk IO device.
  // Block table for IO device.
  vector<DiskBlockTable*> blocktables_;

  int32 region_mask_;                 // Bitmask of available NUMA regions.
  int32 region_count_;                // Count of available NUMA regions.
  int32 region_[32];                  // Pagecount per region.
  int region_mode_;                   // What to do with NUMA hints?
  static const int kLocalNuma = 1;    // Target local memory.
  static const int kRemoteNuma = 2;   // Target remote memory.

  // Results.
  int64 errorcount_;                  // Total hardware incidents seen.
  int statuscount_;                   // Total test errors seen.

  // Thread type constants and types
  enum ThreadType {
    kMemoryType = 0,
    kFileIOType = 1,
    kNetIOType = 2,
    kNetSlaveType = 3,
    kCheckType = 4,
    kInvertType = 5,
    kDiskType = 6,
    kRandomDiskType = 7,
    kCPUType = 8,
    kErrorType = 9,
    kCCType = 10
  };

  // Helper functions.
  virtual void AcquireWorkerLock();
  virtual void ReleaseWorkerLock();
  pthread_mutex_t worker_lock_;  // Lock access to the worker thread structure.
  typedef vector<WorkerThread*> WorkerVector;
  typedef map<int, WorkerVector*> WorkerMap;
  // Contains all worker threads.
  WorkerMap workers_map_;
  // Delay between power spikes.
  time_t pause_delay_;
  // The duration of each pause (for power spikes).
  time_t pause_duration_;
  // For the workers we pause and resume to create power spikes.
  WorkerStatus power_spike_status_;
  // For the workers we never pause.
  WorkerStatus continuous_status_;

  class OsLayer *os_;                   // Os abstraction: put hacks here.
  class PatternList *patternlist_;      // Access to global data patterns.

  // RunAnalysis methods
  void AnalysisAllStats();              // Summary of all runs.
  void MemoryStats();
  void FileStats();
  void NetStats();
  void CheckStats();
  void InvertStats();
  void DiskStats();

  void QueueStats();

  // Physical page use reporting.
  void AddrMapInit();
  void AddrMapUpdate(struct page_entry *pe);
  void AddrMapPrint();

  // additional memory data from google-specific tests.
  virtual void GoogleMemoryStats(float *memcopy_data,
                                 float *memcopy_bandwidth);

  virtual void GoogleOsOptions(std::map<std::string, std::string> *options);

  // Page queues, only one of (valid_+empty_) or (finelock_q_) will be used
  // at a time. A commandline switch controls which queue implementation will
  // be used.
  class PageEntryQueue *valid_;        // Page queue structure, valid pages.
  class PageEntryQueue *empty_;        // Page queue structure, free pages.
  class FineLockPEQueue *finelock_q_;  // Page queue with fine-grain locks
  Sat::PageQueueType pe_q_implementation_;   // Queue implementation switch

  DISALLOW_COPY_AND_ASSIGN(Sat);
};

Sat *SatFactory();

#endif  // STRESSAPPTEST_SAT_H_
