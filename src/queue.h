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

// queue.h : simple queue api

// This is an interface to a simple thread safe queue,
// used to hold data blocks and patterns.
// The order in which the blocks are returned is random.

#ifndef STRESSAPPTEST_QUEUE_H_  // NOLINT
#define STRESSAPPTEST_QUEUE_H_

#include <sys/types.h>
#include <pthread.h>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "sattypes.h"  // NOLINT
#include "pattern.h"   // NOLINT

// Tag indicating no preference.
static const int kDontCareTag = -1;
// Tag indicating no preference.
static const int kInvalidTag = 0xf001;


// This describes a block of memory, and the expected fill pattern.
struct page_entry {
  uint64 offset;
  void *addr;
  uint64 paddr;
  class Pattern *pattern;
  int32 tag;     // These are tags for use in NUMA affinity or other uses.
  uint32 touch;  // Counter of the number of reads from this page.
  uint64 ts;     // Timestamp of the last read from this page.
  class Pattern *lastpattern;  // Expected Pattern at last read.
};

static inline void init_pe(struct page_entry *pe) {
  pe->offset = 0;
  pe->addr = NULL;
  pe->pattern = NULL;
  pe->tag = kInvalidTag;
  pe->touch = 0;
  pe->ts = 0;
  pe->lastpattern = NULL;
}

// This is a threadsafe randomized queue of pages for
// worker threads to use.
class PageEntryQueue {
 public:
  explicit PageEntryQueue(uint64 queuesize);
  ~PageEntryQueue();

  // Push a page onto the list.
  int Push(struct page_entry *pe);
  // Pop a random page off of the list.
  int PopRandom(struct page_entry *pe);

 private:
  struct page_entry *pages_;  // Where the pages are held.
  int64 nextin_;
  int64 nextout_;
  int64 q_size_;  // Size of the queue.
  int64 pushed_;  // Number of pages pushed, total.
  int64 popped_;  // Number of pages popped, total.
  pthread_mutex_t q_mutex_;

  DISALLOW_COPY_AND_ASSIGN(PageEntryQueue);
};


#endif  // MILES_TESTS_SAT_QUEUE_H_ NOLINT
