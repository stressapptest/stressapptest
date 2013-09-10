// Copyright 2010 Google Inc. All Rights Reserved.
// Author: cferris

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef STRESSAPPTEST_CLOCK_H_  // NOLINT
#define STRESSAPPTEST_CLOCK_H_

#include <time.h>

// This class implements a clock that can be overriden for unit tests.
class Clock {
 public:
  virtual ~Clock() {}

  virtual time_t Now() { return time(NULL); }
};

#endif  // STRESSAPPTEST_CLOCK_H_ NOLINT
