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

// error_diag.h: Ambiguous error diagnosis class

#ifndef STRESSAPPTEST_ERROR_DIAG_H_
#define STRESSAPPTEST_ERROR_DIAG_H_

#include <pthread.h>
#include <list>
#include <map>
#include <set>
#include <string>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "sattypes.h"
#include "os.h"

class ErrorInstance;

// This describes the components of the system.
class DeviceTree {
 public:
  explicit DeviceTree(string name);
  ~DeviceTree();

  // Atomically find arbitrary device in subtree.
  DeviceTree *FindInSubTree(string name);
  // Find or add named device.
  DeviceTree *FindOrAddDevice(string name);
  // Atomically add sub device.
  void InsertSubDevice(string name);
  // Returns parent device.
  DeviceTree *GetParent() { return parent_; }
  // Pretty prints device tree.
  void PrettyPrint(string spacer = " ");
  // Atomically add error instance to device.
  void AddErrorInstance(ErrorInstance *error_instance);
  // Returns true of device is known to be bad.
  bool KnownBad();
  // Returns number of direct sub devices.
  int NumDirectSubDevices() { return subdevices_.size(); }

 private:
  // Unlocked version of FindInSubTree.
  DeviceTree *UnlockedFindInSubTree(string name);

  std::map<string, DeviceTree*> subdevices_;    // Map of sub-devices.
  std::list<ErrorInstance*> errors_;            // Log of errors.
  DeviceTree *parent_;                          // Pointer to parent device.
  string name_;                                 // Device name.
  pthread_mutex_t device_tree_mutex_;           // Mutex protecting device tree.
};


// enum type for collected errors.
enum SATErrorType {
  SAT_ERROR_NONE = 0,
  SAT_ERROR_ECC,
  SAT_ERROR_MISCOMPARE,
  SAT_ERROR_SECTOR_TAG,
};

// enum type for error severity.
enum SATErrorSeverity {
  SAT_ERROR_CORRECTABLE = 0,
  SAT_ERROR_FATAL,
};

// This describes an error and it's likely causes.
class ErrorInstance {
 public:
  ErrorInstance(): type_(SAT_ERROR_NONE), severity_(SAT_ERROR_CORRECTABLE) {}

  SATErrorType type_;             // Type of error: ECC, miscompare, sector.
  SATErrorSeverity severity_;     // Correctable, or fatal.
  std::set<DeviceTree*> causes_;  // Devices that can cause this type of error.
};

// This describes ECC errors.
class ECCErrorInstance: public ErrorInstance {
 public:
  ECCErrorInstance() { type_ = SAT_ERROR_ECC; }

  uint64 addr_;               // Address where error occured.
};

// This describes miscompare errors.
class MiscompareErrorInstance: public ErrorInstance {
 public:
  MiscompareErrorInstance() { type_ = SAT_ERROR_MISCOMPARE; }

  uint64 addr_;               // Address where miscompare occured.
};

// This describes HDD miscompare errors.
class HDDMiscompareErrorInstance: public MiscompareErrorInstance {
 public:
  uint64 addr2_;             // addr_ and addr2_ are src and dst memory addr.
  int offset_;               // offset.
  int block_;                // error block.
};

// This describes HDD miscompare errors.
class HDDSectorTagErrorInstance: public ErrorInstance {
 public:
  HDDSectorTagErrorInstance() { type_ = SAT_ERROR_SECTOR_TAG; }

  uint64 addr_;
  uint64 addr2_;             // addr_ and addr2_ are src and dst memory addr.
  int sector_;               // error sector.
  int block_;                // error block.
};

// Generic error storage and sorting class.
class ErrorDiag {
 public:
  ErrorDiag();
  virtual ~ErrorDiag();

  // Add info about a CECC.
  virtual int AddCeccError(string dimm_string);

  // Add info about a UECC.
  virtual int AddUeccError(string dimm_string);

  // Add info about a miscompare.
  virtual int AddMiscompareError(string dimm_string, uint64 addr, int count);

  // Add info about a miscompare from a drive.
  virtual int AddHDDMiscompareError(string devicename, int block, int offset,
                            void *src_addr, void *dst_addr);

  // Add info about a sector tag miscompare from a drive.
  virtual int AddHDDSectorTagError(string devicename, int block, int offset,
                           int sector, void *src_addr, void *dst_addr);

  // Set platform specific handle and initialize device tree.
  bool set_os(OsLayer *os);

 protected:
  // Create and initialize system device tree.
  virtual bool InitializeDeviceTree();

  // Utility Function to translate a virtual address to DIMM number.
  string AddressToDimmString(OsLayer *os, void *addr, int offset);

  DeviceTree *system_tree_root_;  // System device tree.
  OsLayer *os_;                   // Platform handle.

 private:
  DISALLOW_COPY_AND_ASSIGN(ErrorDiag);
};

#endif  // STRESSAPPTEST_ERROR_DIAG_H_
