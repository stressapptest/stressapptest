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

// error_diag.cc: Collects device errors for analysis to more accurately
//                pin-point failed component.

#include <set>
#include <list>
#include <map>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "error_diag.h"
#include "sattypes.h"


// DeviceTree constructor.
DeviceTree::DeviceTree(string name)
  : parent_(0), name_(name) {
  pthread_mutex_init(&device_tree_mutex_, NULL);
}

// DeviceTree destructor.
DeviceTree::~DeviceTree() {
  // Deallocate subtree devices.
  for (std::map<string, DeviceTree*>::iterator itr = subdevices_.begin();
      itr != subdevices_.end();
      ++itr) {
    delete itr->second;
  }
  // Deallocate device errors.
  for (std::list<ErrorInstance*>::iterator itr = errors_.begin();
      itr != errors_.end();
      ++itr) {
    delete (*itr);
  }
  pthread_mutex_destroy(&device_tree_mutex_);
}

// Atomically find named device in sub device tree.
// Returns 0 if not found
DeviceTree *DeviceTree::FindInSubTree(string name) {
  DeviceTree *ret;
  pthread_mutex_lock(&device_tree_mutex_);
  ret = UnlockedFindInSubTree(name);
  pthread_mutex_unlock(&device_tree_mutex_);
  return ret;
}

// Find named device in sub device tree (Non-atomic).
// Returns 0 if not found
DeviceTree *DeviceTree::UnlockedFindInSubTree(string name) {
  std::map<string, DeviceTree*>::iterator itr = subdevices_.find(name);
  if (itr != subdevices_.end()) {
    return itr->second;
  } else {
    // Search sub-tree.
    for (std::map<string, DeviceTree*>::iterator itr = subdevices_.begin();
        itr != subdevices_.end();
        ++itr) {
      DeviceTree *result = itr->second->UnlockedFindInSubTree(name);
      if (result != 0)
        return result;
    }
    return 0;
  }
}

// Atomically add error instance to device.
void DeviceTree::AddErrorInstance(ErrorInstance *error_instance) {
  pthread_mutex_lock(&device_tree_mutex_);
  errors_.push_back(error_instance);
  pthread_mutex_unlock(&device_tree_mutex_);
}

// Find or add queried device as necessary.
DeviceTree *DeviceTree::FindOrAddDevice(string name) {
  // Assume named device does not exist and try to insert the device anyway.
  // No-op if named device already exists.
  InsertSubDevice(name);
  // Find and return sub device pointer.
  return FindInSubTree(name);
}

// Pretty prints device tree.
void DeviceTree::PrettyPrint(string spacer) {
  for (std::map<string, DeviceTree*>::iterator itr = subdevices_.begin();
      itr != subdevices_.end();
      ++itr) {
    printf("%s%s\n", spacer.c_str(), itr->first.c_str());
    itr->second->PrettyPrint(spacer+spacer);
  }
}

// Atomically add sub device.
// No-op if named device already exists.
void DeviceTree::InsertSubDevice(string name) {
  pthread_mutex_lock(&device_tree_mutex_);
  if (UnlockedFindInSubTree(name) != 0) {
    pthread_mutex_unlock(&device_tree_mutex_);
    return;
  }
  subdevices_[name] = new DeviceTree(name);
  subdevices_[name]->parent_ = this;
  pthread_mutex_unlock(&device_tree_mutex_);
}


// Returns true of any error associated with this device is fatal.
bool DeviceTree::KnownBad() {
  pthread_mutex_lock(&device_tree_mutex_);
  for (std::list<ErrorInstance*>::iterator itr = errors_.begin();
      itr != errors_.end();
      ++itr) {
    if ((*itr)->severity_ == SAT_ERROR_FATAL) {
      pthread_mutex_unlock(&device_tree_mutex_);
      return true;
    }
  }
  pthread_mutex_unlock(&device_tree_mutex_);
  return false;
}


// ErrorDiag constructor.
ErrorDiag::ErrorDiag() {
  os_ = 0;
  system_tree_root_ = 0;
}

// ErrorDiag destructor.
ErrorDiag::~ErrorDiag() {
  if (system_tree_root_)
    delete system_tree_root_;
}

// Set platform specific handle and initialize device tree.
// Returns false on error. true otherwise.
bool ErrorDiag::set_os(OsLayer *os) {
  os_ = os;
  return(InitializeDeviceTree());
}

// Create and initialize system device tree.
// Returns false on error. true otherwise.
bool ErrorDiag::InitializeDeviceTree() {
  system_tree_root_ = new DeviceTree("system_root");
  if (!system_tree_root_)
    return false;
  return true;
}

// Logs info about a CECC.
// Returns -1 on error, 1 if diagnoser reports error externally; 0 otherwise.
int ErrorDiag::AddCeccError(string dimm_string) {
  DeviceTree *dimm_device = system_tree_root_->FindOrAddDevice(dimm_string);
  ECCErrorInstance *error = new ECCErrorInstance;
  if (!error)
    return -1;
  error->severity_ = SAT_ERROR_CORRECTABLE;
  dimm_device->AddErrorInstance(error);
  return 0;
}

// Logs info about a UECC.
// Returns -1 on error, 1 if diagnoser reports error externally; 0 otherwise.
int ErrorDiag::AddUeccError(string dimm_string) {
  DeviceTree *dimm_device = system_tree_root_->FindOrAddDevice(dimm_string);
  ECCErrorInstance *error = new ECCErrorInstance;
  if (!error)
    return -1;
  error->severity_ = SAT_ERROR_FATAL;
  dimm_device->AddErrorInstance(error);
  return 0;
}

// Logs info about a miscompare.
// Returns -1 on error, 1 if diagnoser reports error externally; 0 otherwise.
int ErrorDiag::AddMiscompareError(string dimm_string, uint64 addr, int count) {
  DeviceTree *dimm_device = system_tree_root_->FindOrAddDevice(dimm_string);
  MiscompareErrorInstance *error = new MiscompareErrorInstance;
  if (!error)
    return -1;
  error->severity_ = SAT_ERROR_FATAL;
  error->addr_ = addr;
  dimm_device->AddErrorInstance(error);
  os_->ErrorReport(dimm_string.c_str(), "miscompare", count);
  return 1;
}

// Utility Function to translate a virtual address to DIMM number.
// Returns -1 on error, 1 if diagnoser reports error externally; 0 otherwise.
string ErrorDiag::AddressToDimmString(OsLayer *os, void *addr, int offset) {
  char dimm_string[256] = "";
  char *vbyteaddr = reinterpret_cast<char*>(addr) + offset;
  uint64 paddr = os->VirtualToPhysical(vbyteaddr);
  os->FindDimm(paddr, dimm_string, sizeof(dimm_string));
  return string(dimm_string);
}

// Info about a miscompare from a drive.
// Returns -1 on error, 1 if diagnoser reports error externally; 0 otherwise.
int ErrorDiag::AddHDDMiscompareError(string devicename, int block, int offset,
                                     void *src_addr, void *dst_addr) {
  bool mask_hdd_error = false;

  HDDMiscompareErrorInstance *error = new HDDMiscompareErrorInstance;
  if (!error)
    return -1;

  error->addr_ = reinterpret_cast<uint64>(src_addr);
  error->addr2_ = reinterpret_cast<uint64>(dst_addr);
  error->offset_ = offset;
  error->block_ = block;

  string src_dimm = AddressToDimmString(os_, src_addr, offset);
  string dst_dimm = AddressToDimmString(os_, dst_addr, offset);

  // DIMM name look up success
  if (src_dimm.compare("DIMM Unknown")) {
    // Add src DIMM as possible miscompare cause.
    DeviceTree *src_dimm_dev = system_tree_root_->FindOrAddDevice(src_dimm);
    error->causes_.insert(src_dimm_dev);
    if (src_dimm_dev->KnownBad()) {
      mask_hdd_error = true;
      logprintf(5, "Log: supressed %s miscompare report: "
                "known bad source: %s\n", devicename.c_str(), src_dimm.c_str());
    }
  }
  if (dst_dimm.compare("DIMM Unknown")) {
    // Add dst DIMM as possible miscompare cause.
    DeviceTree *dst_dimm_dev = system_tree_root_->FindOrAddDevice(dst_dimm);
    error->causes_.insert(dst_dimm_dev);
    if (dst_dimm_dev->KnownBad()) {
      mask_hdd_error = true;
      logprintf(5, "Log: supressed %s miscompare report: "
                "known bad destination: %s\n", devicename.c_str(),
                dst_dimm.c_str());
    }
  }

  DeviceTree *hdd_dev = system_tree_root_->FindOrAddDevice(devicename);
  hdd_dev->AddErrorInstance(error);

  // HDD error was not masked by bad DIMMs: report bad HDD.
  if (!mask_hdd_error) {
    os_->ErrorReport(devicename.c_str(), "miscompare", 1);
    error->severity_ = SAT_ERROR_FATAL;
    return 1;
  }
  return 0;
}

// Info about a sector tag miscompare from a drive.
// Returns -1 on error, 1 if diagnoser reports error externally; 0 otherwise.
int ErrorDiag::AddHDDSectorTagError(string devicename, int block, int offset,
                                    int sector, void *src_addr,
                                    void *dst_addr) {
  bool mask_hdd_error = false;

  HDDSectorTagErrorInstance *error = new HDDSectorTagErrorInstance;
  if (!error)
    return -1;

  error->addr_ = reinterpret_cast<uint64>(src_addr);
  error->addr2_ = reinterpret_cast<uint64>(dst_addr);
  error->sector_ = sector;
  error->block_ = block;

  string src_dimm = AddressToDimmString(os_, src_addr, offset);
  string dst_dimm = AddressToDimmString(os_, dst_addr, offset);

  // DIMM name look up success
  if (src_dimm.compare("DIMM Unknown")) {
    // Add src DIMM as possible miscompare cause.
    DeviceTree *src_dimm_dev = system_tree_root_->FindOrAddDevice(src_dimm);
    error->causes_.insert(src_dimm_dev);
    if (src_dimm_dev->KnownBad()) {
      mask_hdd_error = true;
      logprintf(5, "Log: supressed %s sector tag error report: "
                "known bad source: %s\n", devicename.c_str(), src_dimm.c_str());
    }
  }
  if (dst_dimm.compare("DIMM Unknown")) {
    // Add dst DIMM as possible miscompare cause.
    DeviceTree *dst_dimm_dev = system_tree_root_->FindOrAddDevice(dst_dimm);
    error->causes_.insert(dst_dimm_dev);
    if (dst_dimm_dev->KnownBad()) {
      mask_hdd_error = true;
      logprintf(5, "Log: supressed %s sector tag error report: "
                "known bad destination: %s\n", devicename.c_str(),
                dst_dimm.c_str());
    }
  }

  DeviceTree *hdd_dev = system_tree_root_->FindOrAddDevice(devicename);
  hdd_dev->AddErrorInstance(error);

  // HDD error was not masked by bad DIMMs: report bad HDD.
  if (!mask_hdd_error) {
    os_->ErrorReport(devicename.c_str(), "sector", 1);
    error->severity_ = SAT_ERROR_FATAL;
    return 1;
  }
  return 0;
}
