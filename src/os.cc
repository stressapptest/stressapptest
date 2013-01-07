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

// os.cc : os and machine specific implementation
// This file includes an abstracted interface
// for linux-distro specific and HW specific
// interfaces.

#include "os.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/types.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ipc.h>
#ifdef HAVE_SYS_SHM_H
#include <sys/shm.h>
#endif
#include <unistd.h>

#ifndef SHM_HUGETLB
#define SHM_HUGETLB      04000  // remove when glibc defines it
#endif

#include <string>
#include <list>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "sattypes.h"
#include "error_diag.h"

// OsLayer initialization.
OsLayer::OsLayer() {
  testmem_ = 0;
  testmemsize_ = 0;
  totalmemsize_ = 0;
  min_hugepages_bytes_ = 0;
  normal_mem_ = true;
  use_hugepages_ = false;
  use_posix_shm_ = false;
  dynamic_mapped_shmem_ = false;
  shmid_ = 0;

  time_initialized_ = 0;

  regionsize_ = 0;
  regioncount_ = 1;
  num_cpus_ = 0;
  num_nodes_ = 0;
  num_cpus_per_node_ = 0;
  error_diagnoser_ = 0;
  err_log_callback_ = 0;
  error_injection_ = false;

  void *pvoid = 0;
  address_mode_ = sizeof(pvoid) * 8;

  has_clflush_ = false;
  has_sse2_ = false;

  use_flush_page_cache_ = false;
}

// OsLayer cleanup.
OsLayer::~OsLayer() {
  if (error_diagnoser_)
    delete error_diagnoser_;
}

// OsLayer initialization.
bool OsLayer::Initialize() {
  time_initialized_ = time(NULL);
  // Detect asm support.
  GetFeatures();

  if (num_cpus_ == 0) {
    num_nodes_ = 1;
    num_cpus_ = sysconf(_SC_NPROCESSORS_ONLN);
    num_cpus_per_node_ = num_cpus_ / num_nodes_;
  }
  logprintf(5, "Log: %d nodes, %d cpus.\n", num_nodes_, num_cpus_);
  sat_assert(CPU_SETSIZE >= num_cpus_);
  cpu_sets_.resize(num_nodes_);
  cpu_sets_valid_.resize(num_nodes_);
  // Create error diagnoser.
  error_diagnoser_ = new ErrorDiag();
  if (!error_diagnoser_->set_os(this))
    return false;
  return true;
}

// Machine type detected. Can we implement all these functions correctly?
bool OsLayer::IsSupported() {
  if (kOpenSource) {
    // There are no explicitly supported systems in open source version.
    return true;
  }

  // This is the default empty implementation.
  // SAT won't report full error information.
  return false;
}

int OsLayer::AddressMode() {
  // Detect 32/64 bit binary.
  void *pvoid = 0;
  return sizeof(pvoid) * 8;
}

// Translates user virtual to physical address.
uint64 OsLayer::VirtualToPhysical(void *vaddr) {
  // Needs platform specific implementation.
  return 0;
}

// Returns the HD device that contains this file.
string OsLayer::FindFileDevice(string filename) {
  return "hdUnknown";
}

// Returns a list of locations corresponding to HD devices.
list<string> OsLayer::FindFileDevices() {
  // No autodetection on unknown systems.
  list<string> locations;
  return locations;
}


// Get HW core features from cpuid instruction.
void OsLayer::GetFeatures() {
#if defined(STRESSAPPTEST_CPU_X86_64) || defined(STRESSAPPTEST_CPU_I686)
  // CPUID features documented at:
  // http://www.sandpile.org/ia32/cpuid.htm
  int ax, bx, cx, dx;
  __asm__ __volatile__ (
      "cpuid": "=a" (ax), "=b" (bx), "=c" (cx), "=d" (dx) : "a" (1));
  has_clflush_ = (dx >> 19) & 1;
  has_sse2_ = (dx >> 26) & 1;

  logprintf(9, "Log: has clflush: %s, has sse2: %s\n",
            has_clflush_ ? "true" : "false",
            has_sse2_ ? "true" : "false");
#elif defined(STRESSAPPTEST_CPU_PPC)
  // All PPC implementations have cache flush instructions.
  has_clflush_ = true;
#elif defined(STRESSAPPTEST_CPU_ARMV7A)
#warning "Unsupported CPU type ARMV7A: unable to determine feature set."
#else
#warning "Unsupported CPU type: unable to determine feature set."
#endif
}


// Enable FlushPageCache to be functional instead of a NOP.
void OsLayer::ActivateFlushPageCache(void) {
  logprintf(9, "Log: page cache will be flushed as needed\n");
  use_flush_page_cache_ = true;
}

// Flush the page cache to ensure reads come from the disk.
bool OsLayer::FlushPageCache(void) {
  if (!use_flush_page_cache_)
    return true;

  // First, ask the kernel to write the cache to the disk.
  sync();

  // Second, ask the kernel to empty the cache by writing "1" to
  // "/proc/sys/vm/drop_caches".
  static const char *drop_caches_file = "/proc/sys/vm/drop_caches";
  int dcfile = open(drop_caches_file, O_WRONLY);
  if (dcfile < 0) {
    int err = errno;
    string errtxt = ErrorString(err);
    logprintf(3, "Log: failed to open %s - err %d (%s)\n",
              drop_caches_file, err, errtxt.c_str());
    return false;
  }

  ssize_t bytes_written = write(dcfile, "1", 1);
  close(dcfile);

  if (bytes_written != 1) {
    int err = errno;
    string errtxt = ErrorString(err);
    logprintf(3, "Log: failed to write %s - err %d (%s)\n",
              drop_caches_file, err, errtxt.c_str());
    return false;
  }
  return true;
}


// We need to flush the cacheline here.
void OsLayer::Flush(void *vaddr) {
  // Use the generic flush. This function is just so we can override
  // this if we are so inclined.
  if (has_clflush_)
    FastFlush(vaddr);
}


// Run C or ASM copy as appropriate..
bool OsLayer::AdlerMemcpyWarm(uint64 *dstmem, uint64 *srcmem,
                              unsigned int size_in_bytes,
                              AdlerChecksum *checksum) {
  if (has_sse2_) {
    return AdlerMemcpyAsm(dstmem, srcmem, size_in_bytes, checksum);
  } else {
    return AdlerMemcpyWarmC(dstmem, srcmem, size_in_bytes, checksum);
  }
}


// Translate user virtual to physical address.
int OsLayer::FindDimm(uint64 addr, char *buf, int len) {
  char tmpbuf[256];
  snprintf(tmpbuf, sizeof(tmpbuf), "DIMM Unknown");
  snprintf(buf, len, "%s", tmpbuf);
  return 0;
}


// Classifies addresses according to "regions"
// This isn't really implemented meaningfully here..
int32 OsLayer::FindRegion(uint64 addr) {
  static bool warned = false;

  if (regionsize_ == 0) {
    regionsize_ = totalmemsize_ / 8;
    if (regionsize_ < 512 * kMegabyte)
      regionsize_ = 512 * kMegabyte;
    regioncount_ = totalmemsize_ / regionsize_;
    if (regioncount_ < 1) regioncount_ = 1;
  }

  int32 region_num = addr / regionsize_;
  if (region_num >= regioncount_) {
    if (!warned) {
        logprintf(0, "Log: region number %d exceeds region count %d\n",
                  region_num, regioncount_);
        warned = true;
    }
    region_num = region_num % regioncount_;
  }
  return region_num;
}

// Report which cores are associated with a given region.
cpu_set_t *OsLayer::FindCoreMask(int32 region) {
  sat_assert(region >= 0);
  region %= num_nodes_;
  if (!cpu_sets_valid_[region]) {
    CPU_ZERO(&cpu_sets_[region]);
    for (int i = 0; i < num_cpus_per_node_; ++i) {
      CPU_SET(i + region * num_cpus_per_node_, &cpu_sets_[region]);
    }
    cpu_sets_valid_[region] = true;
    logprintf(5, "Log: Region %d mask 0x%s\n",
                 region, FindCoreMaskFormat(region).c_str());
  }
  return &cpu_sets_[region];
}

// Return cores associated with a given region in hex string.
string OsLayer::FindCoreMaskFormat(int32 region) {
  cpu_set_t* mask = FindCoreMask(region);
  string format = cpuset_format(mask);
  if (format.size() < 8)
    format = string(8 - format.size(), '0') + format;
  return format;
}

// Report an error in an easily parseable way.
bool OsLayer::ErrorReport(const char *part, const char *symptom, int count) {
  time_t now = time(NULL);
  int ttf = now - time_initialized_;
  logprintf(0, "Report Error: %s : %s : %d : %ds\n", symptom, part, count, ttf);
  return true;
}

// Read the number of hugepages out of the kernel interface in proc.
int64 OsLayer::FindHugePages() {
  char buf[65] = "0";

  // This is a kernel interface to query the numebr of hugepages
  // available in the system.
  static const char *hugepages_info_file = "/proc/sys/vm/nr_hugepages";
  int hpfile = open(hugepages_info_file, O_RDONLY);

  ssize_t bytes_read = read(hpfile, buf, 64);
  close(hpfile);

  if (bytes_read <= 0) {
    logprintf(12, "Log: /proc/sys/vm/nr_hugepages "
                  "read did not provide data\n");
    return 0;
  }

  if (bytes_read == 64) {
    logprintf(0, "Process Error: /proc/sys/vm/nr_hugepages "
                 "is surprisingly large\n");
    return 0;
  }

  // Add a null termintation to be string safe.
  buf[bytes_read] = '\0';
  // Read the page count.
  int64 pages = strtoull(buf, NULL, 10);  // NOLINT

  return pages;
}

int64 OsLayer::FindFreeMemSize() {
  int64 size = 0;
  int64 minsize = 0;
  if (totalmemsize_ > 0)
    return totalmemsize_;

  int64 pages = sysconf(_SC_PHYS_PAGES);
  int64 avpages = sysconf(_SC_AVPHYS_PAGES);
  int64 pagesize = sysconf(_SC_PAGESIZE);
  int64 physsize = pages * pagesize;
  int64 avphyssize = avpages * pagesize;

  // Assume 2MB hugepages.
  int64 hugepagesize = FindHugePages() * 2 * kMegabyte;

  if ((pages == -1) || (pagesize == -1)) {
    logprintf(0, "Process Error: sysconf could not determine memory size.\n");
    return 0;
  }

  // We want to leave enough stuff for things to run.
  // If the user specified a minimum amount of memory to expect, require that.
  // Otherwise, if more than 2GB is present, leave 192M + 5% for other stuff.
  // If less than 2GB is present use 85% of what's available.
  // These are fairly arbitrary numbers that seem to work OK.
  //
  // TODO(nsanders): is there a more correct way to determine target
  // memory size?
  if (hugepagesize > 0 && min_hugepages_bytes_ > 0) {
    minsize = min_hugepages_bytes_;
  } else if (physsize < 2048LL * kMegabyte) {
    minsize = ((pages * 85) / 100) * pagesize;
  } else {
    minsize = ((pages * 95) / 100) * pagesize - (192 * kMegabyte);
  }

  // Use hugepage sizing if available.
  if (hugepagesize > 0) {
    if (hugepagesize < minsize) {
      logprintf(0, "Procedural Error: Not enough hugepages. "
                   "%lldMB available < %lldMB required.\n",
                hugepagesize / kMegabyte,
                minsize / kMegabyte);
      // Require the calculated minimum amount of memory.
      size = minsize;
    } else {
      // Require that we get all hugepages.
      size = hugepagesize;
    }
  } else {
    // Require the calculated minimum amount of memory.
    size = minsize;
  }

  logprintf(5, "Log: Total %lld MB. Free %lld MB. Hugepages %lld MB. "
               "Targeting %lld MB (%lld%%)\n",
            physsize / kMegabyte,
            avphyssize / kMegabyte,
            hugepagesize / kMegabyte,
            size / kMegabyte,
            size * 100 / physsize);

  totalmemsize_ = size;
  return size;
}

// Allocates all memory available.
int64 OsLayer::AllocateAllMem() {
  int64 length = FindFreeMemSize();
  bool retval = AllocateTestMem(length, 0);
  if (retval)
    return length;
  else
    return 0;
}

// Allocate the target memory. This may be from malloc, hugepage pool
// or other platform specific sources.
bool OsLayer::AllocateTestMem(int64 length, uint64 paddr_base) {
  // Try hugepages first.
  void *buf = 0;

  sat_assert(length >= 0);

  if (paddr_base)
    logprintf(0, "Process Error: non zero paddr_base %#llx is not supported,"
              " ignore.\n", paddr_base);

  // Determine optimal memory allocation path.
  bool prefer_hugepages = false;
  bool prefer_posix_shm = false;
  bool prefer_dynamic_mapping = false;

  // Are there enough hugepages?
  int64 hugepagesize = FindHugePages() * 2 * kMegabyte;
  // TODO(nsanders): Is there enough /dev/shm? Is there enough free memeory?
  if ((length >= 1400LL * kMegabyte) && (address_mode_ == 32)) {
    prefer_dynamic_mapping = true;
    prefer_posix_shm = true;
    logprintf(3, "Log: Prefer POSIX shared memory allocation.\n");
    logprintf(3, "Log: You may need to run "
                 "'sudo mount -o remount,size=100\% /dev/shm.'\n");
  } else if (hugepagesize >= length) {
    prefer_hugepages = true;
    logprintf(3, "Log: Prefer using hugepace allocation.\n");
  } else {
    logprintf(3, "Log: Prefer plain malloc memory allocation.\n");
  }

#ifdef HAVE_SYS_SHM_H
  // Allocate hugepage mapped memory.
  if (prefer_hugepages) {
    do { // Allow break statement.
      int shmid;
      void *shmaddr;

      if ((shmid = shmget(2, length,
              SHM_HUGETLB | IPC_CREAT | SHM_R | SHM_W)) < 0) {
        int err = errno;
        string errtxt = ErrorString(err);
        logprintf(3, "Log: failed to allocate shared hugepage "
                      "object - err %d (%s)\n",
                  err, errtxt.c_str());
        logprintf(3, "Log: sysctl -w vm.nr_hugepages=XXX allows hugepages.\n");
        break;
      }

      shmaddr = shmat(shmid, NULL, NULL);
      if (shmaddr == reinterpret_cast<void*>(-1)) {
        int err = errno;
        string errtxt = ErrorString(err);
        logprintf(0, "Log: failed to attach shared "
                     "hugepage object - err %d (%s).\n",
                  err, errtxt.c_str());
        if (shmctl(shmid, IPC_RMID, NULL) < 0) {
          int err = errno;
          string errtxt = ErrorString(err);
          logprintf(0, "Log: failed to remove shared "
                       "hugepage object - err %d (%s).\n",
                    err, errtxt.c_str());
        }
        break;
      }
      use_hugepages_ = true;
      shmid_ = shmid;
      buf = shmaddr;
      logprintf(0, "Log: Using shared hugepage object 0x%x at %p.\n",
                shmid, shmaddr);
    } while (0);
  }

  if ((!use_hugepages_) && prefer_posix_shm) {
    do {
      int shm_object;
      void *shmaddr = NULL;

      shm_object = shm_open("/stressapptest", O_CREAT | O_RDWR, S_IRWXU);
      if (shm_object < 0) {
        int err = errno;
        string errtxt = ErrorString(err);
        logprintf(3, "Log: failed to allocate shared "
                      "smallpage object - err %d (%s)\n",
                  err, errtxt.c_str());
        break;
      }

      if (0 > ftruncate(shm_object, length)) {
        int err = errno;
        string errtxt = ErrorString(err);
        logprintf(3, "Log: failed to ftruncate shared "
                      "smallpage object - err %d (%s)\n",
                  err, errtxt.c_str());
        break;
      }

      // 32 bit linux apps can only use ~1.4G of address space.
      // Use dynamic mapping for allocations larger than that.
      // Currently perf hit is ~10% for this.
      if (prefer_dynamic_mapping) {
        dynamic_mapped_shmem_ = true;
      } else {
        // Do a full mapping here otherwise.
        shmaddr = mmap64(NULL, length, PROT_READ | PROT_WRITE,
                         MAP_SHARED | MAP_NORESERVE | MAP_LOCKED | MAP_POPULATE,
                         shm_object, NULL);
        if (shmaddr == reinterpret_cast<void*>(-1)) {
          int err = errno;
          string errtxt = ErrorString(err);
          logprintf(0, "Log: failed to map shared "
                       "smallpage object - err %d (%s).\n",
                    err, errtxt.c_str());
          break;
        }
      }

      use_posix_shm_ = true;
      shmid_ = shm_object;
      buf = shmaddr;
      char location_message[256] = "";
      if (dynamic_mapped_shmem_) {
        sprintf(location_message, "mapped as needed");
      } else {
        sprintf(location_message, "at %p", shmaddr);
      }
      logprintf(0, "Log: Using posix shared memory object 0x%x %s.\n",
                shm_object, location_message);
    } while (0);
    shm_unlink("/stressapptest");
  }
#endif // HAVE_SYS_SHM_H

  if (!use_hugepages_ && !use_posix_shm_) {
    // Use memalign to ensure that blocks are aligned enough for disk direct IO.
    buf = static_cast<char*>(memalign(4096, length));
    if (buf) {
      logprintf(0, "Log: Using memaligned allocation at %p.\n", buf);
    } else {
      logprintf(0, "Process Error: memalign returned 0\n");
      if ((length >= 1499LL * kMegabyte) && (address_mode_ == 32)) {
        logprintf(0, "Log: You are trying to allocate > 1.4G on a 32 "
                     "bit process. Please setup shared memory.\n");
      }
    }
  }

  testmem_ = buf;
  if (buf || dynamic_mapped_shmem_) {
    testmemsize_ = length;
  } else {
    testmemsize_ = 0;
  }

  return (buf != 0) || dynamic_mapped_shmem_;
}

// Free the test memory.
void OsLayer::FreeTestMem() {
  if (testmem_) {
    if (use_hugepages_) {
#ifdef HAVE_SYS_SHM_H
      shmdt(testmem_);
      shmctl(shmid_, IPC_RMID, NULL);
#endif
    } else if (use_posix_shm_) {
      if (!dynamic_mapped_shmem_) {
        munmap(testmem_, testmemsize_);
      }
      close(shmid_);
    } else {
      free(testmem_);
    }
    testmem_ = 0;
    testmemsize_ = 0;
  }
}


// Prepare the target memory. It may requre mapping in, or this may be a noop.
void *OsLayer::PrepareTestMem(uint64 offset, uint64 length) {
  sat_assert((offset + length) <= testmemsize_);
  if (dynamic_mapped_shmem_) {
    // TODO(nsanders): Check if we can support MAP_NONBLOCK,
    // and evaluate performance hit from not using it.
#ifdef HAVE_MMAP64
    void * mapping = mmap64(NULL, length, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_NORESERVE | MAP_LOCKED | MAP_POPULATE,
                     shmid_, offset);
#else
    void * mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
                     MAP_SHARED | MAP_NORESERVE | MAP_LOCKED | MAP_POPULATE,
                     shmid_, offset);
#endif
    if (mapping == MAP_FAILED) {
      string errtxt = ErrorString(errno);
      logprintf(0, "Process Error: PrepareTestMem mmap64(%llx, %llx) failed. "
                   "error: %s.\n",
                offset, length, errtxt.c_str());
      sat_assert(0);
    }
    return mapping;
  }

  return reinterpret_cast<void*>(reinterpret_cast<char*>(testmem_) + offset);
}

// Release the test memory resources, if any.
void OsLayer::ReleaseTestMem(void *addr, uint64 offset, uint64 length) {
  if (dynamic_mapped_shmem_) {
    int retval = munmap(addr, length);
    if (retval == -1) {
      string errtxt = ErrorString(errno);
      logprintf(0, "Process Error: ReleaseTestMem munmap(%p, %llx) failed. "
                   "error: %s.\n",
                addr, length, errtxt.c_str());
      sat_assert(0);
    }
  }
}

// No error polling on unknown systems.
int OsLayer::ErrorPoll() {
  return 0;
}

// Generally, poll for errors once per second.
void OsLayer::ErrorWait() {
  sat_sleep(1);
  return;
}

// Open a PCI bus-dev-func as a file and return its file descriptor.
// Error is indicated by return value less than zero.
int OsLayer::PciOpen(int bus, int device, int function) {
  char dev_file[256];

  snprintf(dev_file, sizeof(dev_file), "/proc/bus/pci/%02x/%02x.%x",
           bus, device, function);

  int fd = open(dev_file, O_RDWR);
  if (fd == -1) {
    logprintf(0, "Process Error: Unable to open PCI bus %d, device %d, "
                 "function %d (errno %d).\n",
              bus, device, function, errno);
    return -1;
  }

  return fd;
}


// Read and write functions to access PCI config.
uint32 OsLayer::PciRead(int fd, uint32 offset, int width) {
  // Strict aliasing rules lawyers will cause data corruption
  // on cast pointers in some gccs.
  union {
    uint32 l32;
    uint16 l16;
    uint8 l8;
  } datacast;
  datacast.l32 = 0;
  uint32 size = width / 8;

  sat_assert((width == 32) || (width == 16) || (width == 8));
  sat_assert(offset <= (256 - size));

  if (lseek(fd, offset, SEEK_SET) < 0) {
    logprintf(0, "Process Error: Can't seek %x\n", offset);
    return 0;
  }
  if (read(fd, &datacast, size) != static_cast<ssize_t>(size)) {
    logprintf(0, "Process Error: Can't read %x\n", offset);
    return 0;
  }

  // Extract the data.
  switch (width) {
    case 8:
      sat_assert(&(datacast.l8) == reinterpret_cast<uint8*>(&datacast));
      return datacast.l8;
    case 16:
      sat_assert(&(datacast.l16) == reinterpret_cast<uint16*>(&datacast));
      return datacast.l16;
    case 32:
      return datacast.l32;
  }
  return 0;
}

void OsLayer::PciWrite(int fd, uint32 offset, uint32 value, int width) {
  // Strict aliasing rules lawyers will cause data corruption
  // on cast pointers in some gccs.
  union {
    uint32 l32;
    uint16 l16;
    uint8 l8;
  } datacast;
  datacast.l32 = 0;
  uint32 size = width / 8;

  sat_assert((width == 32) || (width == 16) || (width == 8));
  sat_assert(offset <= (256 - size));

  // Cram the data into the right alignment.
  switch (width) {
    case 8:
      sat_assert(&(datacast.l8) == reinterpret_cast<uint8*>(&datacast));
      datacast.l8 = value;
    case 16:
      sat_assert(&(datacast.l16) == reinterpret_cast<uint16*>(&datacast));
      datacast.l16 = value;
    case 32:
      datacast.l32 = value;
  }

  if (lseek(fd, offset, SEEK_SET) < 0) {
    logprintf(0, "Process Error: Can't seek %x\n", offset);
    return;
  }
  if (write(fd, &datacast, size) != static_cast<ssize_t>(size)) {
    logprintf(0, "Process Error: Can't write %x to %x\n", datacast.l32, offset);
    return;
  }

  return;
}



// Open dev msr.
int OsLayer::OpenMSR(uint32 core, uint32 address) {
  char buf[256];
  snprintf(buf, sizeof(buf), "/dev/cpu/%d/msr", core);
  int fd = open(buf, O_RDWR);
  if (fd < 0)
    return fd;

  uint32 pos = lseek(fd, address, SEEK_SET);
  if (pos != address) {
    close(fd);
    logprintf(5, "Log: can't seek to msr %x, cpu %d\n", address, core);
    return -1;
  }

  return fd;
}

bool OsLayer::ReadMSR(uint32 core, uint32 address, uint64 *data) {
  int fd = OpenMSR(core, address);
  if (fd < 0)
    return false;

  // Read from the msr.
  bool res = (sizeof(*data) == read(fd, data, sizeof(*data)));

  if (!res)
    logprintf(5, "Log: Failed to read msr %x core %d\n", address, core);

  close(fd);

  return res;
}

bool OsLayer::WriteMSR(uint32 core, uint32 address, uint64 *data) {
  int fd = OpenMSR(core, address);
  if (fd < 0)
    return false;

  // Write to the msr
  bool res = (sizeof(*data) == write(fd, data, sizeof(*data)));

  if (!res)
    logprintf(5, "Log: Failed to write msr %x core %d\n", address, core);

  close(fd);

  return res;
}

// Extract bits [n+len-1, n] from a 32 bit word.
// so GetBitField(0x0f00, 8, 4) == 0xf.
uint32 OsLayer::GetBitField(uint32 val, uint32 n, uint32 len) {
  return (val >> n) & ((1<<len) - 1);
}

// Generic CPU stress workload that would work on any CPU/Platform.
// Float-point array moving average calculation.
bool OsLayer::CpuStressWorkload() {
  double float_arr[100];
  double sum = 0;
  unsigned int seed = 12345;

  // Initialize array with random numbers.
  for (int i = 0; i < 100; i++) {
#ifdef HAVE_RAND_R
    float_arr[i] = rand_r(&seed);
    if (rand_r(&seed) % 2)
      float_arr[i] *= -1.0;
#else
    float_arr[i] = rand();
    if (rand() % 2)
      float_arr[i] *= -1.0;
#endif
  }

  // Calculate moving average.
  for (int i = 0; i < 100000000; i++) {
    float_arr[i % 100] =
      (float_arr[i % 100] + float_arr[(i + 1) % 100] +
       float_arr[(i + 99) % 100]) / 3;
    sum += float_arr[i % 100];
  }

  // Artificial printf so the loops do not get optimized away.
  if (sum == 0.0)
    logprintf(12, "Log: I'm Feeling Lucky!\n");
  return true;
}

PCIDevices OsLayer::GetPCIDevices() {
  PCIDevices device_list;
  DIR *dir;
  struct dirent *buf = new struct dirent();
  struct dirent *entry;
  dir = opendir(kSysfsPath);
  if (!dir)
    logprintf(0, "Process Error: Cannot open %s", kSysfsPath);
  while (readdir_r(dir, buf, &entry) == 0 && entry) {
    PCIDevice *device;
    unsigned int dev, func;
    // ".", ".." or a special non-device perhaps.
    if (entry->d_name[0] == '.')
      continue;

    device = new PCIDevice();
    if (sscanf(entry->d_name, "%04x:%02hx:%02x.%d",
               &device->domain, &device->bus, &dev, &func) < 4) {
      logprintf(0, "Process Error: Couldn't parse %s", entry->d_name);
      free(device);
      continue;
    }
    device->dev = dev;
    device->func = func;
    device->vendor_id = PCIGetValue(entry->d_name, "vendor");
    device->device_id = PCIGetValue(entry->d_name, "device");
    PCIGetResources(entry->d_name, device);
    device_list.insert(device_list.end(), device);
  }
  closedir(dir);
  delete buf;
  return device_list;
}

int OsLayer::PCIGetValue(string name, string object) {
  int fd, len;
  char filename[256];
  char buf[256];
  snprintf(filename, sizeof(filename), "%s/%s/%s", kSysfsPath,
           name.c_str(), object.c_str());
  fd = open(filename, O_RDONLY);
  if (fd < 0)
    return 0;
  len = read(fd, buf, 256);
  close(fd);
  buf[len] = '\0';
  return strtol(buf, NULL, 0);  // NOLINT
}

int OsLayer::PCIGetResources(string name, PCIDevice *device) {
  char filename[256];
  char buf[256];
  FILE *file;
  int64 start;
  int64 end;
  int64 size;
  int i;
  snprintf(filename, sizeof(filename), "%s/%s/%s", kSysfsPath,
           name.c_str(), "resource");
  file = fopen(filename, "r");
  if (!file) {
    logprintf(0, "Process Error: impossible to find resource file for %s",
              filename);
    return errno;
  }
  for (i = 0; i < 6; i++) {
    if (!fgets(buf, 256, file))
      break;
    sscanf(buf, "%llx %llx", &start, &end);  // NOLINT
    size = 0;
    if (start)
      size = end - start + 1;
    device->base_addr[i] = start;
    device->size[i] = size;
  }
  fclose(file);
  return 0;
}
