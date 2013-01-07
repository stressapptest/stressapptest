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

// worker.h : worker thread interface

// This file contains the Worker Thread class interface
// for the SAT test. Worker Threads implement a repetative
// task used to test or stress the system.

#ifndef STRESSAPPTEST_WORKER_H_
#define STRESSAPPTEST_WORKER_H_

#include <pthread.h>

#include <sys/time.h>
#include <sys/types.h>

#ifdef HAVE_LIBAIO_H
#include <libaio.h>
#endif

#include <queue>
#include <set>
#include <string>
#include <vector>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "disk_blocks.h"
#include "queue.h"
#include "sattypes.h"


// Global Datastruture shared by the Cache Coherency Worker Threads.
struct cc_cacheline_data {
  int *num;
};

// Typical usage:
// (Other workflows may be possible, see function comments for details.)
// - Control thread creates object.
// - Control thread calls AddWorkers(1) for each worker thread.
// - Control thread calls Initialize().
// - Control thread launches worker threads.
// - Every worker thread frequently calls ContinueRunning().
// - Control thread periodically calls PauseWorkers(), effectively sleeps, and
//     then calls ResumeWorkers().
// - Some worker threads may exit early, before StopWorkers() is called.  They
//     call RemoveSelf() after their last call to ContinueRunning().
// - Control thread eventually calls StopWorkers().
// - Worker threads exit.
// - Control thread joins worker threads.
// - Control thread calls Destroy().
// - Control thread destroys object.
//
// Threadsafety:
// - ContinueRunning() may be called concurrently by different workers, but not
//     by a single worker.
// - No other methods may ever be called concurrently, with themselves or
//     eachother.
// - This object may be used by multiple threads only between Initialize() and
//     Destroy().
//
// TODO(matthewb): Move this class and its unittest to their own files.
class WorkerStatus {
 public:
  //--------------------------------
  // Methods for the control thread.
  //--------------------------------

  WorkerStatus() : num_workers_(0), status_(RUN) {}

  // Called by the control thread to increase the worker count.  Must be called
  // before Initialize().  The worker count is 0 upon object initialization.
  void AddWorkers(int num_new_workers) {
    // No need to lock num_workers_mutex_ because this is before Initialize().
    num_workers_ += num_new_workers;
  }

  // Called by the control thread.  May not be called multiple times.  If
  // called, Destroy() must be called before destruction.
  void Initialize();

  // Called by the control thread after joining all worker threads.  Must be
  // called iff Initialize() was called.  No methods may be called after calling
  // this.
  void Destroy();

  // Called by the control thread to tell the workers to pause.  Does not return
  // until all workers have called ContinueRunning() or RemoveSelf().  May only
  // be called between Initialize() and Stop().  Must not be called multiple
  // times without ResumeWorkers() having been called inbetween.
  void PauseWorkers();

  // Called by the control thread to tell the workers to resume from a pause.
  // May only be called between Initialize() and Stop().  May only be called
  // directly after PauseWorkers().
  void ResumeWorkers();

  // Called by the control thread to tell the workers to stop.  May only be
  // called between Initialize() and Destroy().  May only be called once.
  void StopWorkers();

  //--------------------------------
  // Methods for the worker threads.
  //--------------------------------

  // Called by worker threads to decrease the worker count by one.  May only be
  // called between Initialize() and Destroy().  May wait for ResumeWorkers()
  // when called after PauseWorkers().
  void RemoveSelf();

  // Called by worker threads between Initialize() and Destroy().  May be called
  // any number of times.  Return value is whether or not the worker should
  // continue running.  When called after PauseWorkers(), does not return until
  // ResumeWorkers() or StopWorkers() has been called.  Number of distinct
  // calling threads must match the worker count (see AddWorkers() and
  // RemoveSelf()).
  bool ContinueRunning();

  // TODO(matthewb): Is this functionality really necessary?  Remove it if not.
  //
  // This is a hack!  It's like ContinueRunning(), except it won't pause.  If
  // any worker threads use this exclusively in place of ContinueRunning() then
  // PauseWorkers() should never be used!
  bool ContinueRunningNoPause();

 private:
  enum Status { RUN, PAUSE, STOP };

  void WaitOnPauseBarrier() {
#ifdef _POSIX_BARRIERS
    int error = pthread_barrier_wait(&pause_barrier_);
    if (error != PTHREAD_BARRIER_SERIAL_THREAD)
      sat_assert(error == 0);
#endif
  }

  void AcquireNumWorkersLock() {
    sat_assert(0 == pthread_mutex_lock(&num_workers_mutex_));
  }

  void ReleaseNumWorkersLock() {
    sat_assert(0 == pthread_mutex_unlock(&num_workers_mutex_));
  }

  void AcquireStatusReadLock() {
    sat_assert(0 == pthread_rwlock_rdlock(&status_rwlock_));
  }

  void AcquireStatusWriteLock() {
    sat_assert(0 == pthread_rwlock_wrlock(&status_rwlock_));
  }

  void ReleaseStatusLock() {
    sat_assert(0 == pthread_rwlock_unlock(&status_rwlock_));
  }

  Status GetStatus() {
    AcquireStatusReadLock();
    Status status = status_;
    ReleaseStatusLock();
    return status;
  }

  // Returns the previous status.
  Status SetStatus(Status status) {
    AcquireStatusWriteLock();
    Status prev_status = status_;
    status_ = status;
    ReleaseStatusLock();
    return prev_status;
  }

  pthread_mutex_t num_workers_mutex_;
  int num_workers_;

  pthread_rwlock_t status_rwlock_;
  Status status_;

#ifdef _POSIX_BARRIERS
  // Guaranteed to not be in use when (status_ != PAUSE).
  pthread_barrier_t pause_barrier_;
#endif

  DISALLOW_COPY_AND_ASSIGN(WorkerStatus);
};


// This is a base class for worker threads.
// Each thread repeats a specific
// task on various blocks of memory.
class WorkerThread {
 public:
  // Enum to mark a thread as low/med/high priority.
  enum Priority {
    Low,
    Normal,
    High,
  };
  WorkerThread();
  virtual ~WorkerThread();

  // Initialize values and thread ID number.
  virtual void InitThread(int thread_num_init,
                          class Sat *sat_init,
                          class OsLayer *os_init,
                          class PatternList *patternlist_init,
                          WorkerStatus *worker_status);

  // This function is DEPRECATED, it does nothing.
  void SetPriority(Priority priority) { priority_ = priority; }
  // Spawn the worker thread, by running Work().
  int SpawnThread();
  // Only for ThreadSpawnerGeneric().
  void StartRoutine();
  bool InitPriority();

  // Wait for the thread to complete its cleanup.
  virtual bool JoinThread();
  // Kill worker thread with SIGINT.
  virtual bool KillThread();

  // This is the task function that the thread executes.
  // This is implemented per subclass.
  virtual bool Work();

  // Starts per-WorkerThread timer.
  void StartThreadTimer() {gettimeofday(&start_time_, NULL);}
  // Reads current timer value and returns run duration without recording it.
  int64 ReadThreadTimer() {
    struct timeval end_time_;
    gettimeofday(&end_time_, NULL);
    return (end_time_.tv_sec - start_time_.tv_sec)*1000000 +
      (end_time_.tv_usec - start_time_.tv_usec);
  }
  // Stops per-WorkerThread timer and records thread run duration.
  // Start/Stop ThreadTimer repetitively has cumulative effect, ie the timer
  // is effectively paused and restarted, so runduration_usec accumulates on.
  void StopThreadTimer() {
    runduration_usec_ += ReadThreadTimer();
  }

  // Acccess member variables.
  bool GetStatus() {return status_;}
  int64 GetErrorCount() {return errorcount_;}
  int64 GetPageCount() {return pages_copied_;}
  int64 GetRunDurationUSec() {return runduration_usec_;}

  // Returns bandwidth defined as pages_copied / thread_run_durations.
  virtual float GetCopiedData();
  // Calculate worker thread specific copied data.
  virtual float GetMemoryCopiedData() {return 0;}
  virtual float GetDeviceCopiedData() {return 0;}
  // Calculate worker thread specific bandwidth.
  virtual float GetMemoryBandwidth()
    {return GetMemoryCopiedData() / (
        runduration_usec_ * 1.0 / 1000000);}
  virtual float GetDeviceBandwidth()
    {return GetDeviceCopiedData() / (
        runduration_usec_ * 1.0 / 1000000);}

  void set_cpu_mask(cpu_set_t *mask) {
    memcpy(&cpu_mask_, mask, sizeof(*mask));
  }

  void set_cpu_mask_to_cpu(int cpu_num) {
    cpuset_set_ab(&cpu_mask_, cpu_num, cpu_num + 1);
  }

  void set_tag(int32 tag) {tag_ = tag;}

  // Returns CPU mask, where each bit represents a logical cpu.
  bool AvailableCpus(cpu_set_t *cpuset);
  // Returns CPU mask of CPUs this thread is bound to,
  bool CurrentCpus(cpu_set_t *cpuset);
  // Returns Current Cpus mask as string.
  string CurrentCpusFormat() {
    cpu_set_t current_cpus;
    CurrentCpus(&current_cpus);
    return cpuset_format(&current_cpus);
  }

  int ThreadID() {return thread_num_;}

  // Bind worker thread to specified CPU(s)
  bool BindToCpus(const cpu_set_t *cpuset);

 protected:
  // This function dictates whether the main work loop
  // continues, waits, or terminates.
  // All work loops should be of the form:
  //   do {
  //     // work.
  //   } while (IsReadyToRun());
  virtual bool IsReadyToRun() { return worker_status_->ContinueRunning(); }
  // TODO(matthewb): Is this function really necessary? Remove it if not.
  //
  // Like IsReadyToRun(), except it won't pause.
  virtual bool IsReadyToRunNoPause() {
    return worker_status_->ContinueRunningNoPause();
  }

  // These are functions used by the various work loops.
  // Pretty print and log a data miscompare.
  virtual void ProcessError(struct ErrorRecord *er,
                            int priority,
                            const char *message);

  // Compare a region of memory with a known data patter, and report errors.
  virtual int CheckRegion(void *addr,
                          class Pattern *pat,
                          int64 length,
                          int offset,
                          int64 patternoffset);

  // Fast compare a block of memory.
  virtual int CrcCheckPage(struct page_entry *srcpe);

  // Fast copy a block of memory, while verifying correctness.
  virtual int CrcCopyPage(struct page_entry *dstpe,
                          struct page_entry *srcpe);

  // Fast copy a block of memory, while verifying correctness, and heating CPU.
  virtual int CrcWarmCopyPage(struct page_entry *dstpe,
                              struct page_entry *srcpe);

  // Fill a page with its specified pattern.
  virtual bool FillPage(struct page_entry *pe);

  // Copy with address tagging.
  virtual bool AdlerAddrMemcpyC(uint64 *dstmem64,
                                uint64 *srcmem64,
                                unsigned int size_in_bytes,
                                AdlerChecksum *checksum,
                                struct page_entry *pe);
  // SSE copy with address tagging.
  virtual bool AdlerAddrMemcpyWarm(uint64 *dstmem64,
                                   uint64 *srcmem64,
                                   unsigned int size_in_bytes,
                                   AdlerChecksum *checksum,
                                   struct page_entry *pe);
  // Crc data with address tagging.
  virtual bool AdlerAddrCrcC(uint64 *srcmem64,
                             unsigned int size_in_bytes,
                             AdlerChecksum *checksum,
                             struct page_entry *pe);
  // Setup tagging on an existing page.
  virtual bool TagAddrC(uint64 *memwords,
                        unsigned int size_in_bytes);
  // Report a mistagged cacheline.
  virtual bool ReportTagError(uint64 *mem64,
                      uint64 actual,
                      uint64 tag);
  // Print out the error record of the tag mismatch.
  virtual void ProcessTagError(struct ErrorRecord *error,
                       int priority,
                       const char *message);

  // A worker thread can yield itself to give up CPU until it's scheduled again
  bool YieldSelf();

 protected:
  // General state variables that all subclasses need.
  int thread_num_;                  // Thread ID.
  volatile bool status_;            // Error status.
  volatile int64 pages_copied_;     // Recorded for memory bandwidth calc.
  volatile int64 errorcount_;       // Miscompares seen by this thread.

  cpu_set_t cpu_mask_;              // Cores this thread is allowed to run on.
  volatile uint32 tag_;             // Tag hint for memory this thread can use.

  bool tag_mode_;                   // Tag cachelines with vaddr.

  // Thread timing variables.
  struct timeval start_time_;        // Worker thread start time.
  volatile int64 runduration_usec_;  // Worker run duration in u-seconds.

  // Function passed to pthread_create.
  void *(*thread_spawner_)(void *args);
  pthread_t thread_;                // Pthread thread ID.
  Priority priority_;               // Worker thread priority.
  class Sat *sat_;                  // Reference to parent stest object.
  class OsLayer *os_;               // Os abstraction: put hacks here.
  class PatternList *patternlist_;  // Reference to data patterns.

  // Work around style guide ban on sizeof(int).
  static const uint64 iamint_ = 0;
  static const int wordsize_ = sizeof(iamint_);

 private:
  WorkerStatus *worker_status_;

  DISALLOW_COPY_AND_ASSIGN(WorkerThread);
};

// Worker thread to perform File IO.
class FileThread : public WorkerThread {
 public:
  FileThread();
  // Set filename to use for file IO.
  virtual void SetFile(const char *filename_init);
  virtual bool Work();

  // Calculate worker thread specific bandwidth.
  virtual float GetDeviceCopiedData()
    {return GetCopiedData()*2;}
  virtual float GetMemoryCopiedData();

 protected:
  // Record of where these pages were sourced from, and what
  // potentially broken components they passed through.
  struct PageRec {
     struct Pattern *pattern;  // This is the data it should contain.
     void *src;  // This is the memory location the data was sourced from.
     void *dst;  // This is where it ended up.
  };

  // These are functions used by the various work loops.
  // Pretty print and log a data miscompare. Disks require
  // slightly different error handling.
  virtual void ProcessError(struct ErrorRecord *er,
                            int priority,
                            const char *message);

  virtual bool OpenFile(int *pfile);
  virtual bool CloseFile(int fd);

  // Read and write whole file to disk.
  virtual bool WritePages(int fd);
  virtual bool ReadPages(int fd);

  // Read and write pages to disk.
  virtual bool WritePageToFile(int fd, struct page_entry *src);
  virtual bool ReadPageFromFile(int fd, struct page_entry *dst);

  // Sector tagging support.
  virtual bool SectorTagPage(struct page_entry *src, int block);
  virtual bool SectorValidatePage(const struct PageRec &page,
                                  struct page_entry *dst,
                                  int block);

  // Get memory for an incoming data transfer..
  virtual bool PagePrepare();
  // Remove memory allocated for data transfer.
  virtual bool PageTeardown();

  // Get memory for an incoming data transfer..
  virtual bool GetEmptyPage(struct page_entry *dst);
  // Get memory for an outgoing data transfer..
  virtual bool GetValidPage(struct page_entry *dst);
  // Throw out a used empty page.
  virtual bool PutEmptyPage(struct page_entry *src);
  // Throw out a used, filled page.
  virtual bool PutValidPage(struct page_entry *src);


  struct PageRec *page_recs_;          // Array of page records.
  int crc_page_;                        // Page currently being CRC checked.
  string filename_;                     // Name of file to access.
  string devicename_;                   // Name of device file is on.

  bool page_io_;                        // Use page pool for IO.
  void *local_page_;                   // malloc'd page fon non-pool IO.
  int pass_;                            // Number of writes to the file so far.

  // Tag to detect file corruption.
  struct SectorTag {
    volatile uint8 magic;
    volatile uint8 block;
    volatile uint8 sector;
    volatile uint8 pass;
    char pad[512-4];
  };

  DISALLOW_COPY_AND_ASSIGN(FileThread);
};


// Worker thread to perform Network IO.
class NetworkThread : public WorkerThread {
 public:
  NetworkThread();
  // Set hostname to use for net IO.
  virtual void SetIP(const char *ipaddr_init);
  virtual bool Work();

  // Calculate worker thread specific bandwidth.
  virtual float GetDeviceCopiedData()
    {return GetCopiedData()*2;}

 protected:
  // IsReadyToRunNoPause() wrapper, for NetworkSlaveThread to override.
  virtual bool IsNetworkStopSet();
  virtual bool CreateSocket(int *psocket);
  virtual bool CloseSocket(int sock);
  virtual bool Connect(int sock);
  virtual bool SendPage(int sock, struct page_entry *src);
  virtual bool ReceivePage(int sock, struct page_entry *dst);
  char ipaddr_[256];
  int sock_;

 private:
  DISALLOW_COPY_AND_ASSIGN(NetworkThread);
};

// Worker thread to reflect Network IO.
class NetworkSlaveThread : public NetworkThread {
 public:
  NetworkSlaveThread();
  // Set socket for IO.
  virtual void SetSock(int sock);
  virtual bool Work();

 protected:
  virtual bool IsNetworkStopSet();

 private:
  DISALLOW_COPY_AND_ASSIGN(NetworkSlaveThread);
};

// Worker thread to detect incoming Network IO.
class NetworkListenThread : public NetworkThread {
 public:
  NetworkListenThread();
  virtual bool Work();

 private:
  virtual bool Listen();
  virtual bool Wait();
  virtual bool GetConnection(int *pnewsock);
  virtual bool SpawnSlave(int newsock, int threadid);
  virtual bool ReapSlaves();

  // For serviced incoming connections.
  struct ChildWorker {
    WorkerStatus status;
    NetworkSlaveThread thread;
  };
  typedef vector<ChildWorker*> ChildVector;
  ChildVector child_workers_;

  DISALLOW_COPY_AND_ASSIGN(NetworkListenThread);
};

// Worker thread to perform Memory Copy.
class CopyThread : public WorkerThread {
 public:
  CopyThread() {}
  virtual bool Work();
  // Calculate worker thread specific bandwidth.
  virtual float GetMemoryCopiedData()
    {return GetCopiedData()*2;}

 private:
  DISALLOW_COPY_AND_ASSIGN(CopyThread);
};

// Worker thread to perform Memory Invert.
class InvertThread : public WorkerThread {
 public:
  InvertThread() {}
  virtual bool Work();
  // Calculate worker thread specific bandwidth.
  virtual float GetMemoryCopiedData()
    {return GetCopiedData()*4;}

 private:
  virtual int InvertPageUp(struct page_entry *srcpe);
  virtual int InvertPageDown(struct page_entry *srcpe);
  DISALLOW_COPY_AND_ASSIGN(InvertThread);
};

// Worker thread to fill blank pages on startup.
class FillThread : public WorkerThread {
 public:
  FillThread();
  // Set how many pages this thread should fill before exiting.
  virtual void SetFillPages(int64 num_pages_to_fill_init);
  virtual bool Work();

 private:
  // Fill a page with the data pattern in pe->pattern.
  virtual bool FillPageRandom(struct page_entry *pe);
  int64 num_pages_to_fill_;
  DISALLOW_COPY_AND_ASSIGN(FillThread);
};

// Worker thread to verify page data matches pattern data.
// Thread will check and replace pages until "done" flag is set,
// then it will check and discard pages until no more remain.
class CheckThread : public WorkerThread {
 public:
  CheckThread() {}
  virtual bool Work();
  // Calculate worker thread specific bandwidth.
  virtual float GetMemoryCopiedData()
    {return GetCopiedData();}

 private:
  DISALLOW_COPY_AND_ASSIGN(CheckThread);
};


// Worker thread to poll for system error messages.
// Thread will check for messages until "done" flag is set.
class ErrorPollThread : public WorkerThread {
 public:
  ErrorPollThread() {}
  virtual bool Work();

 private:
  DISALLOW_COPY_AND_ASSIGN(ErrorPollThread);
};

// Computation intensive worker thread to stress CPU.
class CpuStressThread : public WorkerThread {
 public:
  CpuStressThread() {}
  virtual bool Work();

 private:
  DISALLOW_COPY_AND_ASSIGN(CpuStressThread);
};

// Worker thread that tests the correctness of the
// CPU Cache Coherency Protocol.
class CpuCacheCoherencyThread : public WorkerThread {
 public:
  CpuCacheCoherencyThread(cc_cacheline_data *cc_data,
                          int cc_cacheline_count_,
                          int cc_thread_num_,
                          int cc_inc_count_);
  virtual bool Work();

 protected:
  cc_cacheline_data *cc_cacheline_data_;  // Datstructure for each cacheline.
  int cc_local_num_;        // Local counter for each thread.
  int cc_cacheline_count_;  // Number of cache lines to operate on.
  int cc_thread_num_;       // The integer id of the thread which is
                            // used as an index into the integer array
                            // of the cacheline datastructure.
  int cc_inc_count_;        // Number of times to increment the counter.

 private:
  DISALLOW_COPY_AND_ASSIGN(CpuCacheCoherencyThread);
};

// Worker thread to perform disk test.
class DiskThread : public WorkerThread {
 public:
  explicit DiskThread(DiskBlockTable *block_table);
  virtual ~DiskThread();
  // Calculate disk thread specific bandwidth.
  virtual float GetDeviceCopiedData() {
    return (blocks_written_ * write_block_size_ +
            blocks_read_ * read_block_size_) / kMegabyte;}

  // Set filename for device file (in /dev).
  virtual void SetDevice(const char *device_name);
  // Set various parameters that control the behaviour of the test.
  virtual bool SetParameters(int read_block_size,
                             int write_block_size,
                             int64 segment_size,
                             int64 cache_size,
                             int blocks_per_segment,
                             int64 read_threshold,
                             int64 write_threshold,
                             int non_destructive);

  virtual bool Work();

  virtual float GetMemoryCopiedData() {return 0;}

 protected:
  static const int kSectorSize = 512;       // Size of sector on disk.
  static const int kBufferAlignment = 512;  // Buffer alignment required by the
                                            // kernel.
  static const int kBlockRetry = 100;       // Number of retries to allocate
                                            // sectors.

  enum IoOp {
    ASYNC_IO_READ   = 0,
    ASYNC_IO_WRITE  = 1
  };

  virtual bool OpenDevice(int *pfile);
  virtual bool CloseDevice(int fd);

  // Retrieves the size (in bytes) of the disk/file.
  virtual bool GetDiskSize(int fd);

  // Retrieves the current time in microseconds.
  virtual int64 GetTime();

  // Do an asynchronous disk I/O operation.
  virtual bool AsyncDiskIO(IoOp op, int fd, void *buf, int64 size,
                           int64 offset, int64 timeout);

  // Write a block to disk.
  virtual bool WriteBlockToDisk(int fd, BlockData *block);

  // Verify a block on disk.
  virtual bool ValidateBlockOnDisk(int fd, BlockData *block);

  // Main work loop.
  virtual bool DoWork(int fd);

  int read_block_size_;       // Size of blocks read from disk, in bytes.
  int write_block_size_;      // Size of blocks written to disk, in bytes.
  int64 blocks_read_;         // Number of blocks read in work loop.
  int64 blocks_written_;      // Number of blocks written in work loop.
  int64 segment_size_;        // Size of disk segments (in bytes) that the disk
                              // will be split into where testing can be
                              // confined to a particular segment.
                              // Allows for control of how evenly the disk will
                              // be tested.  Smaller segments imply more even
                              // testing (less random).
  int blocks_per_segment_;    // Number of blocks that will be tested per
                              // segment.
  int cache_size_;            // Size of disk cache, in bytes.
  int queue_size_;            // Length of in-flight-blocks queue, in blocks.
  int non_destructive_;       // Use non-destructive mode or not.
  int update_block_table_;    // If true, assume this is the thread
                              // responsible for writing the data in the disk
                              // for this block device and, therefore,
                              // update the block table. If false, just use
                              // the block table to get data.

  // read/write times threshold for reporting a problem
  int64 read_threshold_;      // Maximum time a read should take (in us) before
                              // a warning is given.
  int64 write_threshold_;     // Maximum time a write should take (in us) before
                              // a warning is given.
  int64 read_timeout_;        // Maximum time a read can take before a timeout
                              // and the aborting of the read operation.
  int64 write_timeout_;       // Maximum time a write can take before a timeout
                              // and the aborting of the write operation.

  string device_name_;        // Name of device file to access.
  int64 device_sectors_;      // Number of sectors on the device.

  std::queue<BlockData*> in_flight_sectors_;   // Queue of sectors written but
                                                // not verified.
  void *block_buffer_;        // Pointer to aligned block buffer.

#ifdef HAVE_LIBAIO_H
  io_context_t aio_ctx_;     // Asynchronous I/O context for Linux native AIO.
#endif

  DiskBlockTable *block_table_;  // Disk Block Table, shared by all disk
                                 // threads that read / write at the same
                                 // device

  DISALLOW_COPY_AND_ASSIGN(DiskThread);
};

class RandomDiskThread : public DiskThread {
 public:
  explicit RandomDiskThread(DiskBlockTable *block_table);
  virtual ~RandomDiskThread();
  // Main work loop.
  virtual bool DoWork(int fd);
 protected:
  DISALLOW_COPY_AND_ASSIGN(RandomDiskThread);
};

// Worker thread to perform checks in a specific memory region.
class MemoryRegionThread : public WorkerThread {
 public:
  MemoryRegionThread();
  ~MemoryRegionThread();
  virtual bool Work();
  void ProcessError(struct ErrorRecord *error, int priority,
                    const char *message);
  bool SetRegion(void *region, int64 size);
  // Calculate worker thread specific bandwidth.
  virtual float GetMemoryCopiedData()
    {return GetCopiedData();}
  virtual float GetDeviceCopiedData()
    {return GetCopiedData() * 2;}
  void SetIdentifier(string identifier) {
    identifier_ = identifier;
  }

 protected:
  // Page queue for this particular memory region.
  char *region_;
  PageEntryQueue *pages_;
  bool error_injection_;
  int phase_;
  string identifier_;
  static const int kPhaseNoPhase = 0;
  static const int kPhaseCopy = 1;
  static const int kPhaseCheck = 2;

 private:
  DISALLOW_COPY_AND_ASSIGN(MemoryRegionThread);
};

#endif  // STRESSAPPTEST_WORKER_H_
