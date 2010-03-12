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

// This file generates an OS interface class consistant with the
// current machine type. No machine type detection is currently done.

#include <stdlib.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <string.h>

#include <map>
#include <string>

#include "os.h"


// Select the proper OS and hardware interface.
OsLayer *OsLayerFactory(const std::map<std::string, std::string> &options) {
  OsLayer *os = 0;
  os = new OsLayer();

  // Check for memory allocation failure.
  if (!os) {
    logprintf(0, "Process Error: Can't allocate memory\n");
    return 0;
  }
  return os;
}
