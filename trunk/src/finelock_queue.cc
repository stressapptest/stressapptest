// Copyright 2007 Google Inc. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// This is an interface to a simple thread safe container with fine-grain locks,
// used to hold data blocks and patterns.

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "finelock_queue.h"
#include "os.h"

// Page entry queue implementation follows.
// Push and Get functions are analogous to lock and unlock operations on a given
// page entry, while preserving queue semantics.
//
// The actual 'queue' implementation is actually just an array. The entries are
// never shuffled or re-ordered like that of a real queue. Instead, Get
// functions return a random page entry of a given type and lock that particular
// page entry until it is unlocked by corresponding Put functions.
//
// In this implementation, a free page is those page entries where pattern is
// null (pe->pattern == 0)


// Constructor: Allocates memory and initialize locks.
FineLockPEQueue::FineLockPEQueue(
                 uint64 queuesize, int64 pagesize) {
  q_size_ = queuesize;
  pages_ = new struct page_entry[q_size_];
  pagelocks_ = new pthread_mutex_t[q_size_];
  page_size_ = pagesize;

  // What metric should we measure this run.
  queue_metric_ = kTouch;

  {  // Init all the page locks.
    for (uint64 i = 0; i < q_size_; i++) {
        pthread_mutex_init(&(pagelocks_[i]), NULL);
        // Pages start out owned (locked) by Sat::InitializePages.
        // A locked state indicates that the page state is unknown,
        // and the lock should not be aquired. As InitializePages creates
        // the page records, they will be inserted and unlocked, at which point
        // they are ready to be aquired and filled by worker threads.
        sat_assert(pthread_mutex_lock(&(pagelocks_[i])) == 0);
    }
  }

  {  // Init the random number generator.
    for (int i = 0; i < 4; i++) {
      rand_seed_[i] = i + 0xbeef;
      pthread_mutex_init(&(randlocks_[i]), NULL);
    }
  }

  // Try to make a linear congruential generator with our queue size.
  // We need this to deterministically search all the queue (being able to find
  // a single available element is a design requirement), but we don't want to
  // cause any page to be more likley chosen than another. The previous
  // sequential retry heavily biased pages at the beginning of a bunch, or
  // isolated pages surrounded by unqualified ones.
  int64 length = queuesize;
  int64 modlength = length;
  int64 a;
  int64 c;

  if (length < 3) {
    a = 1;
    c = 1;
  } else {
    // Search for a nontrivial generator.
    a = getA(length) % length;
    // If this queue size doesn't have a nontrivial generator (where the
    // multiplier is greater then one) we'll check increasing queue sizes,
    // and discard out of bounds results.
    while (a == 1) {
      modlength++;
      a = getA(modlength) % modlength;
    }
    c = getC(modlength);
  }

  // This is our final generator.
  a_ = a;
  c_ = c;
  modlength_ = modlength;
}

// Part of building a linear congruential generator n1 = (a * n0 + c) % m
// Get 'a', where a - 1 must be divisible by all prime
// factors of 'm', our queue size.
int64 FineLockPEQueue::getA(int64 m) {
  int64 remaining = m;
  int64 a = 1;
  if ((((remaining / 4) * 4) == remaining)) {
    a = 2;
  }
  // For each number, let's see if it's divisible,
  // then divide it out.
  for (int64 i = 2; i <= m; i++) {
    if (((remaining / i) * i) == remaining) {
      remaining /= i;
      // Keep dividing it out until there's no more.
      while (((remaining / i) * i) == remaining)
        remaining /= i;
      a *= i;
    }
  }

  // Return 'a' as specified.
  return (a + 1) % m;
}


// Part of building a linear congruential generator n1 = (a * n0 + c) % m
// Get a prime number approx 3/4 the size of our queue.
int64 FineLockPEQueue::getC(int64 m) {
  // Start here at 3/4.
  int64 start = (3 * m) / 4 + 1;
  int64 possible_prime = start;
  // Keep trying until we find a prime.
  for (possible_prime = start; possible_prime > 1; possible_prime--) {
    bool failed = false;
    for (int64 i = 2; i < possible_prime; i++) {
      if (((possible_prime / i) * i) == possible_prime) {
        failed = true;
        break;
      }
    }
    if (!failed) {
      return possible_prime;
    }
  }
  // One is prime enough.
  return 1;
}

// Destructor: Clean-up allocated memory and destroy pthread locks.
FineLockPEQueue::~FineLockPEQueue() {
  uint64 i;
  for (i = 0; i < q_size_; i++)
    pthread_mutex_destroy(&(pagelocks_[i]));
  delete[] pagelocks_;
  delete[] pages_;
  for (i = 0; i < 4; i++) {
    pthread_mutex_destroy(&(randlocks_[i]));
  }
}


bool FineLockPEQueue::QueueAnalysis() {
  const char *measurement = "Error";
  uint64 buckets[32];

  if (queue_metric_ == kTries)
    measurement = "Failed retrievals";
  else if (queue_metric_ == kTouch)
    measurement = "Reads per page";

  // Buckets for each log2 access counts.
  for (int b = 0; b < 32; b++) {
    buckets[b] = 0;
  }

  // Bucketize the page counts by highest bit set.
  for (uint64 i = 0; i < q_size_; i++) {
    uint32 readcount = pages_[i].touch;
    int b = 0;
    for (b = 0; b < 31; b++) {
      if (readcount < (1u << b))
        break;
    }

    buckets[b]++;
  }

  logprintf(12, "Log:  %s histogram\n", measurement);
  for (int b = 0; b < 32; b++) {
    if (buckets[b])
      logprintf(12, "Log:  %12d - %12d: %12d\n",
          ((1 << b) >> 1), 1 << b, buckets[b]);
  }

  return true;
}

namespace {
// Callback mechanism for exporting last action.
OsLayer *g_os;
FineLockPEQueue *g_fpqueue = 0;

// Global callback to hook into Os object.
bool err_log_callback(uint64 paddr, string *buf) {
  if (g_fpqueue) {
    return g_fpqueue->ErrorLogCallback(paddr, buf);
  }
  return false;
}
}

// Setup global state for exporting callback.
void FineLockPEQueue::set_os(OsLayer *os) {
  g_os = os;
  g_fpqueue = this;
}

OsLayer::ErrCallback FineLockPEQueue::get_err_log_callback() {
  return err_log_callback;
}

// This call is used to export last transaction info on a particular physical
// address.
bool FineLockPEQueue::ErrorLogCallback(uint64 paddr, string *message) {
  struct page_entry pe;
  OsLayer *os = g_os;
  sat_assert(g_os);
  char buf[256];

  // Find the page of this paddr.
  int gotpage = GetPageFromPhysical(paddr, &pe);
  if (!gotpage) {
    return false;
  }

  // Find offset into the page.
  uint64 addr_diff = paddr - pe.paddr;

  // Find vaddr of this paddr. Make sure it matches,
  // as sometimes virtual memory is not contiguous.
  char *vaddr =
    reinterpret_cast<char*>(os->PrepareTestMem(pe.offset, page_size_));
  uint64 new_paddr = os->VirtualToPhysical(vaddr + addr_diff);
  os->ReleaseTestMem(vaddr, pe.offset, page_size_);

  // Is the physical address at this page offset the same as
  // the physical address we were given?
  if (new_paddr != paddr) {
    return false;
  }

  // Print all the info associated with this page.
  message->assign(" (Last Transaction:");

  if (pe.lastpattern) {
    int offset = addr_diff / 8;
    datacast_t data;

    data.l32.l = pe.lastpattern->pattern(offset << 1);
    data.l32.h = pe.lastpattern->pattern((offset << 1) + 1);

    snprintf(buf, sizeof(buf), " %s data=%#016llx",
                  pe.lastpattern->name(), data.l64);
    message->append(buf);
  }
  snprintf(buf, sizeof(buf), " tsc=%#llx)", pe.ts);
  message->append(buf);
  return true;
}

bool FineLockPEQueue::GetPageFromPhysical(uint64 paddr,
                                          struct page_entry *pe) {
  // Traverse through array until finding a page
  // that contains the address we want..
  for (uint64 i = 0; i < q_size_; i++) {
    uint64 page_addr = pages_[i].paddr;
    // This assumes linear vaddr.
    if ((page_addr <= paddr) && (page_addr + page_size_ > paddr)) {
      *pe = pages_[i];
      return true;
    }
  }
  return false;
}


// Get a random number from the slot we locked.
uint64 FineLockPEQueue::GetRandom64FromSlot(int slot) {
  // 64 bit LCG numbers suggested on the internets by
  // http://nuclear.llnl.gov/CNP/rng/rngman/node4.html and others.
  uint64 result = 2862933555777941757ULL * rand_seed_[slot] + 3037000493ULL;
  rand_seed_[slot] = result;
  return result;
}

// Get a random number, we have 4 generators to choose from so hopefully we
// won't be blocking on this.
uint64 FineLockPEQueue::GetRandom64() {
  // Try each available slot.
  for (int i = 0; i < 4; i++) {
    if (pthread_mutex_trylock(&(randlocks_[i])) == 0) {
      uint64 result = GetRandom64FromSlot(i);
      pthread_mutex_unlock(&(randlocks_[i]));
      return result;
    }
  }
  // Forget it, just wait.
  int i = 0;
  if (pthread_mutex_lock(&(randlocks_[i])) == 0) {
    uint64 result = GetRandom64FromSlot(i);
    pthread_mutex_unlock(&(randlocks_[i]));
    return result;
  }

  logprintf(0, "Process Error: Could not acquire random lock.\n");
  sat_assert(0);
  return 0;
}


// Helper function to get a random page entry with given predicate,
// ie, page_is_valid() or page_is_empty() as defined in finelock_queue.h.
//
// Setting tag to a value other than kDontCareTag (-1)
// indicates that we need a tag match, otherwise any tag will do.
//
// Returns true on success, false on failure.
bool FineLockPEQueue::GetRandomWithPredicateTag(struct page_entry *pe,
                      bool (*pred_func)(struct page_entry*),
                      int32 tag) {
  if (!pe || !q_size_)
    return false;

  // Randomly index into page entry array.
  uint64 first_try = GetRandom64() % q_size_;
  uint64 next_try = 1;

  // Traverse through array until finding a page meeting given predicate.
  for (uint64 i = 0; i < q_size_; i++) {
    uint64 index = (next_try + first_try) % q_size_;
    // Go through the loop linear conguentially. We are offsetting by
    // 'first_try' so this path will be a different sequence for every
    // initioal value chosen.
    next_try = (a_ * next_try + c_) % (modlength_);
    while (next_try >= q_size_) {
      // If we have chosen a modlength greater than the queue size,
      // discard out of bounds results.
      next_try = (a_ * next_try + c_) % (modlength_);
    }

    // If page does not meet predicate, don't trylock (expensive).
    if (!(pred_func)(&pages_[index]))
      continue;

    // If page does not meet tag predicate, don't trylock (expensive).
    if ((tag != kDontCareTag) && !(pages_[index].tag & tag))
      continue;

    if (pthread_mutex_trylock(&(pagelocks_[index])) == 0) {
      // If page property (valid/empty) changes before successfully locking,
      // release page and move on.
      if (!(pred_func)(&pages_[index])) {
        pthread_mutex_unlock(&(pagelocks_[index]));
        continue;
      } else {
        // A page entry with given predicate is locked, returns success.
        *pe = pages_[index];

        // Add metrics as necessary.
        if (pred_func == page_is_valid) {
          // Measure time to fetch valid page.
          if (queue_metric_ == kTries)
            pe->touch = i;
          // Measure number of times each page is read.
          if (queue_metric_ == kTouch)
            pe->touch++;
        }

        return true;
      }
    }
  }

  return false;
}

// Without tag hint.
bool FineLockPEQueue::GetRandomWithPredicate(struct page_entry *pe,
                      bool (*pred_func)(struct page_entry*)) {
  return GetRandomWithPredicateTag(pe, pred_func, kDontCareTag);
}


// GetValid() randomly finds a valid page, locks it and returns page entry by
// pointer.
//
// Returns true on success, false on failure.
bool FineLockPEQueue::GetValid(struct page_entry *pe) {
  return GetRandomWithPredicate(pe, page_is_valid);
}

bool FineLockPEQueue::GetValid(struct page_entry *pe, int32 mask) {
  return GetRandomWithPredicateTag(pe, page_is_valid, mask);
}

// GetEmpty() randomly finds an empty page, locks it and returns page entry by
// pointer.
//
// Returns true on success, false on failure.
bool FineLockPEQueue::GetEmpty(struct page_entry *pe, int32 mask) {
  return GetRandomWithPredicateTag(pe, page_is_empty, mask);
}
bool FineLockPEQueue::GetEmpty(struct page_entry *pe) {
  return GetRandomWithPredicate(pe, page_is_empty);
}

// PutEmpty puts an empty page back into the queue, making it available by
// releasing the per-page-entry lock.
//
// Returns true on success, false on failure.
bool FineLockPEQueue::PutEmpty(struct page_entry *pe) {
  if (!pe || !q_size_)
    return false;

  int64 index = pe->offset / page_size_;
  if (!valid_index(index))
    return false;

  pages_[index] = *pe;
  // Enforce that page entry is indeed empty.
  pages_[index].pattern = 0;
  return (pthread_mutex_unlock(&(pagelocks_[index])) == 0);
}

// PutValid puts a valid page back into the queue, making it available by
// releasing the per-page-entry lock.
//
// Returns true on success, false on failure.
bool FineLockPEQueue::PutValid(struct page_entry *pe) {
  if (!pe || !page_is_valid(pe) || !q_size_)
    return false;

  int64 index = pe->offset / page_size_;
  if (!valid_index(index))
    return false;

  pages_[index] = *pe;
  return (pthread_mutex_unlock(&(pagelocks_[index])) == 0);
}
