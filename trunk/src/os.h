// Copyright 2006 Google Inc. All Rights Reserved.
// Author: nsanders, menderico

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef STRESSAPPTEST_OS_H_  // NOLINT
#define STRESSAPPTEST_OS_H_

#include <dirent.h>
#include <string>
#include <list>
#include <map>
#include <vector>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "adler32memcpy.h"  // NOLINT
#include "sattypes.h"       // NOLINT

const char kSysfsPath[] = "/sys/bus/pci/devices";

struct PCIDevice {
  int32 domain;
  uint16 bus;
  uint8 dev;
  uint8 func;
  uint16 vendor_id;
  uint16 device_id;
  uint64 base_addr[6];
  uint64 size[6];
};

typedef vector<PCIDevice*> PCIDevices;

class ErrorDiag;

// This class implements OS/Platform specific funtions.
class OsLayer {
 public:
  OsLayer();
  virtual ~OsLayer();

  // Set the minimum amount of hugepages that should be available for testing.
  // Must be set before Initialize().
  void SetMinimumHugepagesSize(int64 min_bytes) {
    min_hugepages_bytes_ = min_bytes;
  }

  // Initializes data strctures and open files.
  // Returns false on error.
  virtual bool Initialize();

  // Virtual to physical. This implementation is optional for
  // subclasses to implement.
  // Takes a pointer, and returns the corresponding bus address.
  virtual uint64 VirtualToPhysical(void *vaddr);

  // Prints failed dimm. This implementation is optional for
  // subclasses to implement.
  // Takes a bus address and string, and prints the DIMM name
  // into the string. Returns error status.
  virtual int FindDimm(uint64 addr, char *buf, int len);
  // Print dimm info, plus more available info.
  virtual int FindDimmExtended(uint64 addr, char *buf, int len) {
    return FindDimm(addr, buf, len);
  }


  // Classifies addresses according to "regions"
  // This may mean different things on different platforms.
  virtual int32 FindRegion(uint64 paddr);
  // Find cpu cores associated with a region. Either NUMA or arbitrary.
  virtual cpu_set_t *FindCoreMask(int32 region);
  // Return cpu cores associated with a region in a hex string.
  virtual string FindCoreMaskFormat(int32 region);

  // Returns the HD device that contains this file.
  virtual string FindFileDevice(string filename);

  // Returns a list of paths coresponding to HD devices found on this machine.
  virtual list<string> FindFileDevices();

  // Polls for errors. This implementation is optional.
  // This will poll once for errors and return zero iff no errors were found.
  virtual int ErrorPoll();

  // Delay an appropriate amount of time between polling.
  virtual void ErrorWait();

  // Report errors. This implementation is mandatory.
  // This will output a machine readable line regarding the error.
  virtual bool ErrorReport(const char *part, const char *symptom, int count);

  // Flushes page cache. Used to circumvent the page cache when doing disk
  // I/O.  This will be a NOP until ActivateFlushPageCache() is called, which
  // is typically done when opening a file with O_DIRECT fails.
  // Returns false on error, true on success or NOP.
  // Subclasses may implement this in machine specific ways..
  virtual bool FlushPageCache(void);
  // Enable FlushPageCache() to actually do the flush instead of being a NOP.
  virtual void ActivateFlushPageCache(void);

  // Flushes cacheline. Used to distinguish read or write errors.
  // Subclasses may implement this in machine specific ways..
  // Takes a pointer, and flushed the cacheline containing that pointer.
  virtual void Flush(void *vaddr);

  // Fast flush, for use in performance critical code.
  // This is bound at compile time, and will not pick up
  // any runtime machine configuration info.
  inline static void FastFlush(void *vaddr) {
#ifdef STRESSAPPTEST_CPU_PPC
    asm volatile("dcbf 0,%0; sync" : : "r" (vaddr));
#elif defined(STRESSAPPTEST_CPU_X86_64) || defined(STRESSAPPTEST_CPU_I686)
    // Put mfence before and after clflush to make sure:
    // 1. The write before the clflush is committed to memory bus;
    // 2. The read after the clflush is hitting the memory bus.
    //
    // From Intel manual:
    // CLFLUSH is only ordered by the MFENCE instruction. It is not guaranteed
    // to be ordered by any other fencing, serializing or other CLFLUSH
    // instruction. For example, software can use an MFENCE instruction to
    // insure that previous stores are included in the write-back.
    asm volatile("mfence");
    asm volatile("clflush (%0)" :: "r" (vaddr));
    asm volatile("mfence");
#elif defined(STRESSAPPTEST_CPU_ARMV7A)
  #warning "Unsupported CPU type ARMV7A: Unable to force cache flushes."
#else
  #warning "Unsupported CPU type: Unable to force cache flushes."
#endif
  }

  // Get time in cpu timer ticks. Useful for matching MCEs with software
  // actions.
  inline static uint64 GetTimestamp(void) {
    uint64 tsc;
#ifdef STRESSAPPTEST_CPU_PPC
    uint32 tbl, tbu, temp;
    __asm __volatile(
      "1:\n"
      "mftbu  %2\n"
      "mftb   %0\n"
      "mftbu  %1\n"
      "cmpw   %2,%1\n"
      "bne    1b\n"
      : "=r"(tbl), "=r"(tbu), "=r"(temp)
      :
      : "cc");

    tsc = (static_cast<uint64>(tbu) << 32) | static_cast<uint64>(tbl);
#elif defined(STRESSAPPTEST_CPU_X86_64) || defined(STRESSAPPTEST_CPU_I686)
    datacast_t data;
    __asm __volatile("rdtsc" : "=a" (data.l32.l), "=d"(data.l32.h));
    tsc = data.l64;
#elif defined(STRESSAPPTEST_CPU_ARMV7A)
  #warning "Unsupported CPU type ARMV7A: your build may not function correctly"
    tsc = 0;
#else
  #warning "Unsupported CPU type: your build may not function correctly"
    tsc = 0;
#endif
    return (tsc);
  }

  // Find the free memory on the machine.
  virtual int64 FindFreeMemSize();

  // Allocates test memory of length bytes.
  // Subclasses must implement this.
  // Call PepareTestMem to get a pointer.
  virtual int64 AllocateAllMem();  // Returns length.
  // Returns success.
  virtual bool AllocateTestMem(int64 length, uint64 paddr_base);
  virtual void FreeTestMem();

  // Prepares the memory for use. You must call this
  // before using test memory, and after you are done.
  virtual void *PrepareTestMem(uint64 offset, uint64 length);
  virtual void ReleaseTestMem(void *addr, uint64 offset, uint64 length);

  // Machine type detected. Can we implement all these functions correctly?
  // Returns true if machine type is detected and implemented.
  virtual bool IsSupported();

  // Returns 32 for 32-bit, 64 for 64-bit.
  virtual int AddressMode();
  // Update OsLayer state regarding cpu support for various features.
  virtual void GetFeatures();

  // Open, read, write pci cfg through /proc/bus/pci. fd is /proc/pci file.
  virtual int PciOpen(int bus, int device, int function);
  virtual void PciWrite(int fd, uint32 offset, uint32 value, int width);
  virtual uint32 PciRead(int fd, uint32 offset, int width);

  // Read MSRs
  virtual bool ReadMSR(uint32 core, uint32 address, uint64 *data);
  virtual bool WriteMSR(uint32 core, uint32 address, uint64 *data);

  // Extract bits [n+len-1, n] from a 32 bit word.
  // so GetBitField(0x0f00, 8, 4) == 0xf.
  virtual uint32 GetBitField(uint32 val, uint32 n, uint32 len);

  // Platform and CPU specific CPU-stressing function.
  // Returns true on success, false otherwise.
  virtual bool CpuStressWorkload();

  // Causes false errors for unittesting.
  // Setting to "true" causes errors to be injected.
  void set_error_injection(bool errors) { error_injection_ = errors; }
  bool error_injection() const { return error_injection_; }

  // Is SAT using normal malloc'd memory, or exotic mmap'd memory.
  bool normal_mem() const { return normal_mem_; }

  // Get numa config, if available..
  int num_nodes() const { return num_nodes_; }
  int num_cpus() const { return num_cpus_; }

  // Handle to platform-specific error diagnoser.
  ErrorDiag *error_diagnoser_;

  // Detect all PCI Devices.
  virtual PCIDevices GetPCIDevices();

  // Disambiguate between different "warm" memcopies.
  virtual bool AdlerMemcpyWarm(uint64 *dstmem, uint64 *srcmem,
                               unsigned int size_in_bytes,
                               AdlerChecksum *checksum);

  // Store a callback to use to print
  // app-specific info about the last error location.
  // This call back is called with a physical address, and the app can fill in
  // the most recent transaction that occurred at that address.
  typedef bool (*ErrCallback)(uint64 paddr, string *buf);
  void set_err_log_callback(
    ErrCallback err_log_callback) {
    err_log_callback_ = err_log_callback;
  }
  ErrCallback get_err_log_callback() { return err_log_callback_; }

 protected:
  void *testmem_;                // Location of test memory.
  uint64 testmemsize_;           // Size of test memory.
  int64 totalmemsize_;           // Size of available memory.
  int64 min_hugepages_bytes_;    // Minimum hugepages size.
  bool  error_injection_;        // Do error injection?
  bool  normal_mem_;             // Memory DMA capable?
  bool  use_hugepages_;          // Use hugepage shmem?
  bool  use_posix_shm_;          // Use 4k page shmem?
  bool  dynamic_mapped_shmem_;   // Conserve virtual address space.
  int   shmid_;                  // Handle to shmem

  int64 regionsize_;             // Size of memory "regions"
  int   regioncount_;            // Number of memory "regions"
  int   num_cpus_;               // Number of cpus in the system.
  int   num_nodes_;              // Number of nodes in the system.
  int   num_cpus_per_node_;      // Number of cpus per node in the system.
  int   address_mode_;           // Are we running 32 or 64 bit?
  bool  has_sse2_;               // Do we have sse2 instructions?
  bool  has_clflush_;            // Do we have clflush instructions?
  bool  use_flush_page_cache_;   // Do we need to flush the page cache?


  time_t time_initialized_;      // Start time of test.

  vector<cpu_set_t> cpu_sets_;   // Cache for cpu masks.
  vector<bool> cpu_sets_valid_;  // If the cpu mask cache is valid.

  // Get file descriptor for dev msr.
  virtual int OpenMSR(uint32 core, uint32 address);
  // Auxiliary methods for PCI device configuration
  int PCIGetValue(string name, string object);
  int PCIGetResources(string name, PCIDevice *device);

  // Look up how many hugepages there are.
  virtual int64 FindHugePages();

  // Link to find last transaction at an error location.
  ErrCallback err_log_callback_;

 private:
  DISALLOW_COPY_AND_ASSIGN(OsLayer);
};

// Selects and returns the proper OS and hardware interface.  Does not call
// OsLayer::Initialize() on the new object.
OsLayer *OsLayerFactory(const std::map<std::string, std::string> &options);

#endif  // STRESSAPPTEST_OS_H_ NOLINT
