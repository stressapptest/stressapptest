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

// pattern.cc : library of stressful data patterns

#include <sys/types.h>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "pattern.h"
#include "sattypes.h"

// Static data patterns.

static unsigned int walkingOnes_data[] =   {
  0x00000001, 0x00000002, 0x00000004, 0x00000008,
  0x00000010, 0x00000020, 0x00000040, 0x00000080,
  0x00000100, 0x00000200, 0x00000400, 0x00000800,
  0x00001000, 0x00002000, 0x00004000, 0x00008000,
  0x00010000, 0x00020000, 0x00040000, 0x00080000,
  0x00100000, 0x00200000, 0x00400000, 0x00800000,
  0x01000000, 0x02000000, 0x04000000, 0x08000000,
  0x10000000, 0x20000000, 0x40000000, 0x80000000,
  0x40000000, 0x20000000, 0x10000000, 0x08000000,
  0x04000000, 0x02000000, 0x01000000, 0x00800000,
  0x00400000, 0x00200000, 0x00100000, 0x00080000,
  0x00040000, 0x00020000, 0x00010000, 0x00008000,
  0x00004000, 0x00002000, 0x00001000, 0x00000800,
  0x00000400, 0x00000200, 0x00000100, 0x00000080,
  0x00000040, 0x00000020, 0x00000010, 0x00000008,
  0x00000004, 0x00000002, 0x00000001, 0x00000000
};
static const struct PatternData walkingOnes = {
  "walkingOnes",
  walkingOnes_data,
  (sizeof walkingOnes_data / sizeof walkingOnes_data[0]) - 1,
  {1, 1, 2, 1}  // Weight for choosing 32/64/128/256 bit wide of this pattern
};

static unsigned int walkingInvOnes_data[] =   {
  0x00000001, 0xfffffffe, 0x00000002, 0xfffffffd,
  0x00000004, 0xfffffffb, 0x00000008, 0xfffffff7,
  0x00000010, 0xffffffef, 0x00000020, 0xffffffdf,
  0x00000040, 0xffffffbf, 0x00000080, 0xffffff7f,
  0x00000100, 0xfffffeff, 0x00000200, 0xfffffdff,
  0x00000400, 0xfffffbff, 0x00000800, 0xfffff7ff,
  0x00001000, 0xffffefff, 0x00002000, 0xffffdfff,
  0x00004000, 0xffffbfff, 0x00008000, 0xffff7fff,
  0x00010000, 0xfffeffff, 0x00020000, 0xfffdffff,
  0x00040000, 0xfffbffff, 0x00080000, 0xfff7ffff,
  0x00100000, 0xffefffff, 0x00200000, 0xffdfffff,
  0x00400000, 0xffbfffff, 0x00800000, 0xff7fffff,
  0x01000000, 0xfeffffff, 0x02000000, 0xfdffffff,
  0x04000000, 0xfbffffff, 0x08000000, 0xf7ffffff,
  0x10000000, 0xefffffff, 0x20000000, 0xdfffffff,
  0x40000000, 0xbfffffff, 0x80000000, 0x7fffffff,
  0x40000000, 0xbfffffff, 0x20000000, 0xdfffffff,
  0x10000000, 0xefffffff, 0x08000000, 0xf7ffffff,
  0x04000000, 0xfbffffff, 0x02000000, 0xfdffffff,
  0x01000000, 0xfeffffff, 0x00800000, 0xff7fffff,
  0x00400000, 0xffbfffff, 0x00200000, 0xffdfffff,
  0x00100000, 0xffefffff, 0x00080000, 0xfff7ffff,
  0x00040000, 0xfffbffff, 0x00020000, 0xfffdffff,
  0x00010000, 0xfffeffff, 0x00008000, 0xffff7fff,
  0x00004000, 0xffffbfff, 0x00002000, 0xffffdfff,
  0x00001000, 0xffffefff, 0x00000800, 0xfffff7ff,
  0x00000400, 0xfffffbff, 0x00000200, 0xfffffdff,
  0x00000100, 0xfffffeff, 0x00000080, 0xffffff7f,
  0x00000040, 0xffffffbf, 0x00000020, 0xffffffdf,
  0x00000010, 0xffffffef, 0x00000008, 0xfffffff7,
  0x00000004, 0xfffffffb, 0x00000002, 0xfffffffd,
  0x00000001, 0xfffffffe, 0x00000000, 0xffffffff
};
static const struct PatternData walkingInvOnes = {
  "walkingInvOnes",
  walkingInvOnes_data,
  (sizeof walkingInvOnes_data / sizeof walkingInvOnes_data[0]) - 1,
  {2, 2, 5, 5}
};

static unsigned int walkingZeros_data[] =   {
  0xfffffffe, 0xfffffffd, 0xfffffffb, 0xfffffff7,
  0xffffffef, 0xffffffdf, 0xffffffbf, 0xffffff7f,
  0xfffffeff, 0xfffffdff, 0xfffffbff, 0xfffff7ff,
  0xffffefff, 0xffffdfff, 0xffffbfff, 0xffff7fff,
  0xfffeffff, 0xfffdffff, 0xfffbffff, 0xfff7ffff,
  0xffefffff, 0xffdfffff, 0xffbfffff, 0xff7fffff,
  0xfeffffff, 0xfdffffff, 0xfbffffff, 0xf7ffffff,
  0xefffffff, 0xdfffffff, 0xbfffffff, 0x7fffffff,
  0xbfffffff, 0xdfffffff, 0xefffffff, 0xf7ffffff,
  0xfbffffff, 0xfdffffff, 0xfeffffff, 0xff7fffff,
  0xffbfffff, 0xffdfffff, 0xffefffff, 0xfff7ffff,
  0xfffbffff, 0xfffdffff, 0xfffeffff, 0xffff7fff,
  0xffffbfff, 0xffffdfff, 0xffffefff, 0xfffff7ff,
  0xfffffbff, 0xfffffdff, 0xfffffeff, 0xffffff7f,
  0xffffffbf, 0xffffffdf, 0xffffffef, 0xfffffff7,
  0xfffffffb, 0xfffffffd, 0xfffffffe, 0xffffffff
};
static const struct PatternData walkingZeros = {
  "walkingZeros",
  walkingZeros_data,
  (sizeof walkingZeros_data / sizeof walkingZeros_data[0]) - 1,
  {1, 1, 2, 1}
};

static unsigned int OneZero_data[] =   { 0x00000000, 0xffffffff};
static const struct PatternData OneZero = {
  "OneZero",
  OneZero_data,
  (sizeof OneZero_data / sizeof OneZero_data[0]) - 1,
  {5, 5, 15, 5}
};

static unsigned int JustZero_data[] =   { 0x00000000, 0x00000000};
static const struct PatternData JustZero = {
  "JustZero",
  JustZero_data,
  (sizeof JustZero_data / sizeof JustZero_data[0]) - 1,
  {2, 0, 0, 0}
};

static unsigned int JustOne_data[] =   { 0xffffffff, 0xffffffff};
static const struct PatternData JustOne = {
  "JustOne",
  JustOne_data,
  (sizeof JustOne_data / sizeof JustOne_data[0]) - 1,
  {2, 0, 0, 0}
};

static unsigned int JustFive_data[] =   { 0x55555555, 0x55555555};
static const struct PatternData JustFive = {
  "JustFive",
  JustFive_data,
  (sizeof JustFive_data / sizeof JustFive_data[0]) - 1,
  {2, 0, 0, 0}
};

static unsigned int JustA_data[] =   { 0xaaaaaaaa, 0xaaaaaaaa};
static const struct PatternData JustA = {
  "JustA",
  JustA_data,
  (sizeof JustA_data / sizeof JustA_data[0]) - 1,
  {2, 0, 0, 0}
};

static unsigned int FiveA_data[] =   { 0x55555555, 0xaaaaaaaa};
static const struct PatternData FiveA = {
  "FiveA",
  FiveA_data,
  (sizeof FiveA_data / sizeof FiveA_data[0]) - 1,
  {1, 1, 1, 1}
};

static unsigned int FiveA8_data[] =   {
  0x5aa5a55a, 0xa55a5aa5, 0xa55a5aa5, 0x5aa5a55a
};
static const struct PatternData FiveA8 = {
  "FiveA8",
  FiveA8_data,
  (sizeof FiveA8_data / sizeof FiveA8_data[0]) - 1,
  {1, 1, 1, 1}
};

static unsigned int Long8b10b_data[] =   { 0x16161616, 0x16161616 };
static const struct PatternData Long8b10b = {
  "Long8b10b",
  Long8b10b_data,
  (sizeof Long8b10b_data / sizeof Long8b10b_data[0]) - 1,
  {2, 0, 0, 0}
};

static unsigned int Short8b10b_data[] =   { 0xb5b5b5b5, 0xb5b5b5b5 };
static const struct PatternData Short8b10b = {
  "Short8b10b",
  Short8b10b_data,
  (sizeof Short8b10b_data / sizeof Short8b10b_data[0]) - 1,
  {2, 0, 0, 0}
};

static unsigned int Checker8b10b_data[] =   { 0xb5b5b5b5, 0x4a4a4a4a };
static const struct PatternData Checker8b10b = {
  "Checker8b10b",
  Checker8b10b_data,
  (sizeof Checker8b10b_data / sizeof Checker8b10b_data[0]) - 1,
  {1, 0, 0, 1}
};

static unsigned int Five7_data[] =   { 0x55555557, 0x55575555 };
static const struct PatternData Five7 = {
  "Five7",
  Five7_data,
  (sizeof Five7_data / sizeof Five7_data[0]) - 1,
  {0, 2, 0, 0}
};

static unsigned int Zero2fd_data[] =   { 0x00020002, 0xfffdfffd };
static const struct PatternData Zero2fd = {
  "Zero2fd",
  Zero2fd_data,
  (sizeof Zero2fd_data / sizeof Zero2fd_data[0]) - 1,
  {0, 2, 0, 0}
};

// Extern array of useable patterns.
static const struct PatternData pattern_array[] = {
  walkingOnes,
  walkingInvOnes,
  walkingZeros,
  OneZero,
  JustZero,
  JustOne,
  JustFive,
  JustA,
  FiveA,
  FiveA8,
  Long8b10b,
  Short8b10b,
  Checker8b10b,
  Five7,
  Zero2fd,
};
static const int pattern_array_size =
    sizeof pattern_array / sizeof pattern_array[0];

Pattern::Pattern() {
  crc_ = NULL;
}

Pattern::~Pattern() {
  if (crc_ != NULL) {
    delete crc_;
  }
}

// Calculate CRC for this pattern. This must match
// the CRC calculation in worker.cc.
int Pattern::CalculateCrc() {
  // TODO(johnhuang):
  // Consider refactoring to the form:
  // while (i < count) AdlerInc(uint64, uint64, AdlerChecksum*)
  uint64 a1 = 1;
  uint64 a2 = 1;
  uint64 b1 = 0;
  uint64 b2 = 0;

  // checksum is calculated using only the first 4096 bytes of data.
  int i = 0;
  int blocksize = 4096;
  int count = blocksize / sizeof i;
  while (i < count) {
    a1 += pattern(i);
    b1 += a1;
    i++;
    a1 += pattern(i);
    b1 += a1;
    i++;

    a2 += pattern(i);
    b2 += a2;
    i++;
    a2 += pattern(i);
    b2 += a2;
    i++;
  }
  if (crc_ != NULL) {
    delete crc_;
  }
  crc_ = new AdlerChecksum();
  crc_->Set(a1, a2, b1, b2);
  return 0;
}

// Initialize pattern's CRC.
int Pattern::Initialize(const struct PatternData &pattern_init,
                        int buswidth,
                        bool invert,
                        int weight) {
  int result = 1;

  pattern_ = &pattern_init;
  busshift_ = 2;
  inverse_ = invert;
  weight_ = weight;

  name_.clear();
  name_.append(pattern_->name);

  if (invert)
    name_.append("~");

  if (buswidth == 32) {
    name_.append("32");
    busshift_ = 0;
  } else if (buswidth == 64) {
    name_.append("64");
    busshift_ = 1;
  } else if (buswidth == 128) {
    name_.append("128");
    busshift_ = 2;
  } else if (buswidth == 256) {
    name_.append("256");
    busshift_ = 3;
  } else {
    logprintf(0, "Process Error: Confused by bus width %d\n",
              buswidth);
    name_.append("Broken");
    result = 0;
  }

  CalculateCrc();

  return result;
}


PatternList::PatternList() {
  size_= 0;
  initialized_ = 0;
}

PatternList::~PatternList() {
  if (initialized_) {
    Destroy();
  }
}

// Fill in the class with references to the static data patterns
int PatternList::Initialize() {
  int patterncount = 0;
  int weightcount = 0;

  patterns_.resize(pattern_array_size * 8);
  for (int i = 0; i < pattern_array_size; i++) {
    // Non inverted.
    weightcount += pattern_array[i].weight[0];
    patterns_[patterncount++].Initialize(pattern_array[i], 32, false,
                                         pattern_array[i].weight[0]);
    weightcount += pattern_array[i].weight[1];
    patterns_[patterncount++].Initialize(pattern_array[i], 64, false,
                                         pattern_array[i].weight[1]);
    weightcount += pattern_array[i].weight[2];
    patterns_[patterncount++].Initialize(pattern_array[i], 128, false,
                                         pattern_array[i].weight[2]);
    weightcount += pattern_array[i].weight[3];
    patterns_[patterncount++].Initialize(pattern_array[i], 256, false,
                                         pattern_array[i].weight[3]);

    // Inverted.
    weightcount += pattern_array[i].weight[0];
    patterns_[patterncount++].Initialize(pattern_array[i], 32, true,
                                         pattern_array[i].weight[0]);
    weightcount += pattern_array[i].weight[1];
    patterns_[patterncount++].Initialize(pattern_array[i], 64, true,
                                         pattern_array[i].weight[1]);
    weightcount += pattern_array[i].weight[2];
    patterns_[patterncount++].Initialize(pattern_array[i], 128, true,
                                         pattern_array[i].weight[2]);
    weightcount += pattern_array[i].weight[3];
    patterns_[patterncount++].Initialize(pattern_array[i], 256, true,
                                         pattern_array[i].weight[3]);
  }
  size_ = patterncount;
  weightcount_ = weightcount;
  initialized_ = 1;

  logprintf(12, "Log: initialized %d data patterns\n", size_);

  return 1;
}

// Free the stuff.
int PatternList::Destroy() {
  if (!initialized_)
    return 0;

  patterns_.clear();
  size_ = 0;
  initialized_ = 0;

  return 1;
}

// Return pattern numbered "i"
Pattern *PatternList::GetPattern(int i) {
  if (static_cast<unsigned int>(i) < size_) {
    return &patterns_[i];
  }

  logprintf(0, "Process Error: Out of bounds pattern access\n");
  return 0;
}

// Return a randomly selected pattern.
Pattern *PatternList::GetRandomPattern() {
  unsigned int target = random();
  target = target % weightcount_;

  unsigned int i = 0;
  unsigned int sum = 0;
  while (target > sum) {
    sum += patterns_[i].weight();
    i++;
  }
  if (i < size_) {
    return &patterns_[i];
  }

  logprintf(0, "Process Error: Out of bounds pattern access\n");
  return 0;
}
