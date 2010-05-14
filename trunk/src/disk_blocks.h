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
// This file must work with autoconf on its public version,
// so these includes are correct.
#include "pattern.h"

// Data about a block written to disk so that it can be verified later.
class BlockData {
 public:
  BlockData();
  ~BlockData();
  void SetParameters(int64 address, int64 size);
  void IncreaseReferenceCounter();
  void DecreaseReferenceCounter();
  int GetReferenceCounter();
  void SetBlockAsInitialized();
  bool BlockIsInitialized();
  int64 GetAddress();
  int64 GetSize();
  void SetPattern(Pattern *p);
  Pattern *GetPattern();
 protected:
  int64 addr_;         // address of first sector in block
  int64 size_;         // size of block
  int references_;      // reference counter
  bool initialized_;     // flag indicating the block was written on disk
  Pattern *pattern_;
  pthread_mutex_t data_mutex_;
  DISALLOW_COPY_AND_ASSIGN(BlockData);
};

// Disk Block table - store data from blocks to be write / read by
// a DiskThread
class DiskBlockTable {
 public:
  DiskBlockTable();
  virtual ~DiskBlockTable();

  // Get Number of elements stored on table
  int64 NumElems();
  // Clean all table data
  void CleanTable();
  // Get a random block from the list. Only returns if a element
  // is available (consider that other thread must have added them.
  BlockData *GetRandomBlock();
  // Set all initial parameters. Assumes all existent data is
  // invalid and, therefore, must be removed.
  void SetParameters(int sector_size, int write_block_size,
                     int64 device_sectors,
                     int64 segment_size,
                     string device_name);
  // Return a new block in a unused address.
  BlockData *GetUnusedBlock(int64 segment);
  // Remove block from structure (called by write threads)
  int RemoveBlock(BlockData *block);
  // Release block to be erased (called by random threads)
  int ReleaseBlock(BlockData *block);

 protected:

  void InsertOnStructure(BlockData *block);
  //  Generate a random 64-bit integer (virtual so it could be
  //  override by the tests)
  virtual int64 Random64();

  struct StorageData {
    BlockData *block;
    int pos;
  };

  static const int kBlockRetry = 100;       // Number of retries to allocate
                                            // sectors.

  typedef map<int64, StorageData*> AddrToBlockMap;
  typedef vector<int64> PosToAddrVector;
  PosToAddrVector pos_to_addr_;
  AddrToBlockMap addr_to_block_;
  uint64 nelems_;
  int sector_size_;          // Sector size, in bytes
  int write_block_size_;     // Block size, in bytes
  string device_name_;       // Device name
  int64 device_sectors_;     // Number of sectors in device
  int64 segment_size_;       // Segment size, in bytes
  pthread_mutex_t data_mutex_;
  pthread_cond_t data_condition_;
  pthread_mutex_t parameter_mutex_;
  DISALLOW_COPY_AND_ASSIGN(DiskBlockTable);
};

#endif  // STRESSAPPTEST_BLOCKS_H_
