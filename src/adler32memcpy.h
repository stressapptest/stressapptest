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

#ifndef STRESSAPPTEST_ADLER32MEMCPY_H_
#define STRESSAPPTEST_ADLER32MEMCPY_H_

#include <string>
#include "sattypes.h"

// Encapsulation for Adler checksum. Please see adler32memcpy.cc for more
// detail on the adler checksum algorithm.
class AdlerChecksum {
 public:
  AdlerChecksum() {}
  ~AdlerChecksum() {}
  // Returns true if the checksums are equal.
  bool Equals(const AdlerChecksum &other) const;
  // Returns string representation of the Adler checksum
  string ToHexString() const;
  // Sets components of the Adler checksum.
  void Set(uint64 a1, uint64 a2, uint64 b1, uint64 b2);

 private:
  // Components of Adler checksum.
  uint64 a1_, a2_, b1_, b2_;

  DISALLOW_COPY_AND_ASSIGN(AdlerChecksum);
};

// Calculates Adler checksum for supplied data.
bool CalculateAdlerChecksum(uint64 *data64, unsigned int size_in_bytes,
                            AdlerChecksum *checksum);

// C implementation of Adler memory copy.
bool AdlerMemcpyC(uint64 *dstmem64, uint64 *srcmem64,
                    unsigned int size_in_bytes, AdlerChecksum *checksum);

// C implementation of Adler memory copy with some float point ops,
// attempting to warm up the CPU.
bool AdlerMemcpyWarmC(uint64 *dstmem64, uint64 *srcmem64,
                      unsigned int size_in_bytes, AdlerChecksum *checksum);

// x86_64 SSE2 assembly implementation of fast and stressful Adler memory copy.
bool AdlerMemcpyAsm(uint64 *dstmem64, uint64 *srcmem64,
                    unsigned int size_in_bytes, AdlerChecksum *checksum);


#endif  // STRESSAPPTEST_ADLER32MEMCPY_H_
