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

// pattern.h : global pattern references and initialization

// This file implements easy access to statically declared
// data patterns.

#ifndef STRESSAPPTEST_PATTERN_H_
#define STRESSAPPTEST_PATTERN_H_

#include <vector>
#include <string>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "adler32memcpy.h"
#include "sattypes.h"

// 2 = 128 bit bus, 1 = 64 bit bus, 0 = 32 bit bus
const int kBusShift = 2;

// Pattern and CRC data structure
struct PatternData {
  const char *name;          // Name of this pattern.
  unsigned int *pat;         // Data array.
  unsigned int mask;         // Size - 1. data[index & mask] is always valid.
  unsigned char weight[4];   // Weighted frequency of this pattern.
                             // Each pattern has 32,64,128,256 width versions.
                             // All weights are added up, a random number is
                             // chosen between 0-sum(weights), and the
                             // appropriate pattern is chosen. Thus a weight of
                             // 1 is rare, a weight of 10 is 2x as likely to be
                             // chosen as a weight of 5.
};

// Data structure to access data patterns.
class Pattern {
 public:
  Pattern();
  ~Pattern();
  // Fill pattern data and calculate CRC.
  int Initialize(const struct PatternData &pattern_init,
                 int buswidth,
                 bool invert,
                 int weight);

  // Access data members.
  // "busshift_" allows for repeating each pattern word 1, 2, 4, etc. times.
  // in order to create patterns of different width.
  unsigned int pattern(unsigned int offset) {
    unsigned int data = pattern_->pat[(offset >> busshift_) & pattern_->mask];
    if (inverse_)
      data = ~data;
    return data;
  }
  const AdlerChecksum *crc() {return crc_;}
  unsigned int mask() {return pattern_->mask;}
  unsigned int weight() {return weight_;}
  const char *name() {return name_.c_str();}

 private:
  int CalculateCrc();
  const struct PatternData *pattern_;
  int busshift_;        // Target data bus width.
  bool inverse_;        // Invert the data from the original pattern.
  AdlerChecksum *crc_;  // CRC of this pattern.
  string name_;         // The human readable pattern name.
  int weight_;          // This is the likelihood that this
                        // pattern will be chosen.
  // We want to copy this!
  // DISALLOW_COPY_AND_ASSIGN(Pattern);
};

// Object used to access global pattern list.
class PatternList {
 public:
  PatternList();
  ~PatternList();
  // Initialize pointers to global data patterns, and calculate CRC.
  int Initialize();
  int Destroy();

  // Return the pattern designated by index i.
  Pattern *GetPattern(int i);
  // Return a random pattern according to the specified weighted probability.
  Pattern *GetRandomPattern();
  // Return the number of patterns available.
  int Size() {return size_;}

 private:
  vector<class Pattern> patterns_;
  int weightcount_;  // Total count of pattern weights.
  unsigned int size_;
  int initialized_;
  DISALLOW_COPY_AND_ASSIGN(PatternList);
};

// CrcIncrement allows an abstracted way to add a 32bit
// value into a running CRC. This function should be fast, and
// generate meaningful CRCs for the types of data patterns that
// we are using here.
// This CRC formula may not be optimal, but it does work.
// It may be improved in the future.
static inline uint32 CrcIncrement(uint32 crc, uint32 expected, int index) {
  uint32 addition = (expected ^ index);
  uint32 carry = (addition & crc) >> 31;

  return crc + addition + carry;
}


#endif  // STRESSAPPTEST_PATTERN_H_
