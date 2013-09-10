/* Copyright 2013 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


/*
 * This "tool" can be used to brute force the XOR bitmask that a memory
 * controller uses to interleave addresses onto its two channels. To use it,
 * you need to have a bunch of addresses that are known to go to only one
 * of the memory channels... easiest way to get these is to run stressapptest on
 * a machine while holding a soldering iron close to the chips of one channel.
 * Generate about a thousand failures and extract their physical addresses
 * from the output. Write them to findmask.inc in a way that forms a valid
 * definition for the addrs array. Make and run on a big machine.
 *
 * The program iterates over all possible bitmasks within the first NUM_BITS,
 * parallelizing execution over NUM_THREADS. Every integer is masked
 * onto all supplied addresses, counting the amount of times this results in
 * an odd or even amount of bits. If all but NOISE addresses fall on one side,
 * it will print that mask to stdout. Note that the script will always "find"
 * the mask 0x0, and may also report masks such as 0x100000000 depending on
 * your test machines memory size... you will need to use your own judgement to
 * interpret the results.
 *
 * As the program might run for a long time, you can send SIGUSR1 to it to
 * output the last mask that was processed and get a rough idea of the
 * current progress.
 */

#include <inttypes.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

#define NOISE 20
#define NUM_BITS 32
#define NUM_THREADS 128  // keep this a power of two

static uint64_t addrs[] = {
#include "findmask.inc"
};
static uint64_t lastmask;

__attribute__((optimize(3, "unroll-loops")))
void* thread_func(void* arg) {
  register uint64_t mask;
  register uintptr_t num = (uintptr_t)arg;

  for (mask = num; mask < (1ULL << (NUM_BITS + 1)); mask += NUM_THREADS) {
    register const uint64_t* cur;
    register int a = 0;
    register int b = 0;

    for (cur = addrs; (char*)cur < (char*)addrs + sizeof(addrs); cur++) {
#ifdef __x86_64__
      register uint64_t addr asm("rdx") = *cur & mask;
      register uint32_t tmp asm("ebx");

      // Behold: the dark bit counting magic!
      asm (
        // Fold high and low 32 bits onto each other
        "MOVl %%edx, %%ebx\n\t"
        "SHRq $32, %%rdx\n\t"
        "XORl %%ebx, %%edx\n\t"
        // Fold high and low 16 bits onto each other
        "MOVl %%edx, %%ebx\n\t"
        "SHRl $16, %%edx\n\t"
        "XORw %%bx, %%dx\n\t"
        // Fold high and low 8 bits onto each other
        "XORb %%dh, %%dl\n\t"
        // Invoke ancient 8086 parity flag (only counts lowest byte)
        "SETnp %%bl\n\t"
        "SETp %%dl\n\t"
        // Stupid SET instruction can only affect the lowest byte...
        "ANDl $1, %%ebx\n\t"
        "ANDl $1, %%edx\n\t"
        // Increment either 'a' or 'b' without needing another branch
        "ADDl %%ebx, %2\n\t"
        "ADDl %%edx, %1\n\t"
        : "=b" (tmp), "+r"(a), "+r"(b) : "d"(addr) : "cc");

#else  // generic processor
      register uint64_t addr = *cur & mask;
      register uint32_t low = (uint32_t)addr;
      register uint32_t high = (uint32_t)(addr >> 32);

      // Takes about twice as long as the version above... take that GCC!
      __builtin_parity(low) ^ __builtin_parity(high) ? a++ : b++;
#endif

      // Early abort: probably still the most valuable optimization in here
      if (a >= NOISE && b >= NOISE) break;
    }

    if (a < NOISE) b = a;
    if (b < NOISE) {
      printf("Found mask with just %d deviations: 0x%" PRIx64 "\n", b, mask);
      fflush(stdout);
    }

    // I'm a little paranoid about performance: don't write to memory too often
    if (!(mask & 0x7ff)) lastmask = mask;
  }

  return 0;
}

void signal_handler(int signum) {
  printf("Received signal... currently evaluating mask 0x%" PRIx64 "!\n",
         lastmask);
  fflush(stdout);
}

int main(int argc, char** argv) {
  uintptr_t i;
  pthread_t threads[NUM_THREADS];

  signal(SIGUSR1, signal_handler);

  for (i = 0; i < NUM_THREADS; i++)
    pthread_create(&threads[i], 0, thread_func, (void*)i);

  for (i = 0; i < NUM_THREADS; i++)
    pthread_join(threads[i], 0);

  return 0;
}
