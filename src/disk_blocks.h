// Copyright 2008 Google Inc. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Interface for a thread-safe container of disk blocks

#ifndef STRESSAPPTEST_DISK_BLOCKS_H_
#define STRESSAPPTEST_DISK_BLOCKS_H_

#include <sys/types.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <map>
#include <vector>
#include <string>

#include "sattypes.h"

class Pattern;

// Data about a block written to disk so that it can be verified later.
// Thread-unsafe, must be used with locks on non-const methods,
// except for initialized accessor/mutator, which are thread-safe
// (and in fact, is the only method supposed to be accessed from
// someone which is not the thread-safe DiskBlockTable).
class BlockData {
 public:
  BlockData();
  ~BlockData();

  // These are reference counters used to control how many
  // threads currently have a copy of this particular block.
  void IncreaseReferenceCounter() { references_++; }
  void DecreaseReferenceCounter() { references_--; }
  int GetReferenceCounter() const { return references_; }

  // Controls whether the block was written on disk or not.
  // Once written, you cannot "un-written" then without destroying
  // this object.
  void set_initialized();
  bool initialized() const;

  // Accessor methods for some data related to blocks.
  void set_address(uint64 address) { address_ = address; }
  uint64 address() const { return address_; }
  void set_size(uint64 size) { size_ = size; }
  uint64 size() const { return size_; }
  void set_pattern(Pattern *p) { pattern_ = p; }
  Pattern *pattern() { return pattern_; }
 private:
  uint64 address_;  // Address of first sector in block
  uint64 size_;  // Size of block
  int references_;  // Reference counter
  bool initialized_;  // Flag indicating the block was written on disk
  Pattern *pattern_;
  mutable pthread_mutex_t data_mutex_;
  DISALLOW_COPY_AND_ASSIGN(BlockData);
};

// A thread-safe table used to store block data and control access
// to these blocks, letting several threads read and write blocks on
// disk.
class DiskBlockTable {
 public:
  DiskBlockTable();
  virtual ~DiskBlockTable();

  // Returns number of elements stored on table.
  uint64 Size();

  // Sets all initial parameters. Assumes all existent data is
  // invalid and, therefore, must be removed.
  void SetParameters(int sector_size, int write_block_size,
                     int64 device_sectors,
                     int64 segment_size,
                     const string& device_name);

  // During the regular execution, there will be 2 types of threads:
  // - Write thread:  gets a large number of blocks using GetUnusedBlock,
  //                  writes them on disk (if on destructive mode),
  //                  reads block content ONCE from disk and them removes
  //                  the block from queue with RemoveBlock. After a removal a
  //                  block is not available for read threads, but it is
  //                  only removed from memory if there is no reference for
  //                  this block. Note that a write thread also counts as
  //                  a reference.
  // - Read threads:  get one block at a time (if available) with
  //                  GetRandomBlock, reads its content from disk,
  //                  checking whether it is correct or not, and releases
  //                  (Using ReleaseBlock) the block to be erased by the
  //                  write threads. Since several read threads are allowed
  //                  to read the same block, a reference counter is used to
  //                  control when the block can be REALLY erased from
  //                  memory, and all memory management is made by a
  //                  DiskBlockTable instance.

  // Returns a new block in a unused address. Does not
  // grant ownership of the pointer to the caller
  // (use RemoveBlock to delete the block from memory instead).
  BlockData *GetUnusedBlock(int64 segment);

  // Removes block from structure (called by write threads). Returns
  // 1 if successful, 0 otherwise.
  int RemoveBlock(BlockData *block);

  // Gets a random block from the list. Only returns if an element
  // is available (a write thread has got this block, written it on disk,
  // and set this block as initialized). Does not grant ownership of the
  // pointer to the caller (use RemoveBlock to delete the block from
  // memory instead).
  BlockData *GetRandomBlock();

  // Releases block to be erased (called by random threads). Returns
  // 1 if successful, 0 otherwise.
  int ReleaseBlock(BlockData *block);

 protected:
  struct StorageData {
    BlockData *block;
    int pos;
  };
  typedef map<int64, StorageData*> AddrToBlockMap;
  typedef vector<int64> PosToAddrVector;

  // Inserts block in structure, used in tests and by other methods.
  void InsertOnStructure(BlockData *block);

  // Generates a random 64-bit integer.
  // Virtual method so it can be overridden by the tests.
  virtual int64 Random64();

  // Accessor methods for testing.
  const PosToAddrVector& pos_to_addr() const { return pos_to_addr_; }
  const AddrToBlockMap& addr_to_block() const { return addr_to_block_; }

  int sector_size() const { return sector_size_; }
  int write_block_size() const { return write_block_size_; }
  const string& device_name() const { return device_name_; }
  int64 device_sectors() const { return device_sectors_; }
  int64 segment_size() const { return segment_size_; }

 private:
  // Number of retries to allocate sectors.
  static const int kBlockRetry = 100;
  // Actual tables.
  PosToAddrVector pos_to_addr_;
  AddrToBlockMap addr_to_block_;

  // Configuration parameters for block selection
  int sector_size_;  // Sector size, in bytes
  int write_block_size_;  // Block size, in bytes
  string device_name_;  // Device name
  int64 device_sectors_;  // Number of sectors in device
  int64 segment_size_;  // Segment size in bytes
  uint64 size_;  // Number of elements on table
  pthread_mutex_t data_mutex_;
  pthread_cond_t data_condition_;
  pthread_mutex_t parameter_mutex_;
  DISALLOW_COPY_AND_ASSIGN(DiskBlockTable);
};

#endif  // STRESSAPPTEST_BLOCKS_H_
