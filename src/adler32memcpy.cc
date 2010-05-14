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

#include "adler32memcpy.h"

// We are using (a modified form of) adler-32 checksum algorithm instead
// of CRC since adler-32 is faster than CRC.
// (Comparison: http://guru.multimedia.cx/crc32-vs-adler32/)
// This form of adler is bit modified, instead of treating the data in
// units of bytes, 32-bit data is taken as a unit and two 64-bit
// checksums are done (we could have one checksum but two checksums
// make the code run faster).

// Adler-32 implementation:
//   Data is treated as 1-byte numbers and,
//   there are two 16-bit numbers a and b
//   Initialize a with 1 and b with 0.
//   for each data unit 'd'
//      a += d
//      b += a
//   checksum = a<<16 + b
//   This sum should never overflow.
//
// Adler-64+64 implementation:
//   (applied in this code)
//   Data is treated as 32-bit numbers and whole data is separated into two
//   streams, and hence the two checksums a1, a2, b1 and b2.
//   Initialize a1 and a2 with 1, b1 and b2 with 0
//   add first dataunit to a1
//   add a1 to b1
//   add second dataunit to a1
//   add a1 to b1
//   add third dataunit to a2
//   add a2 to b2
//   add fourth dataunit to a2
//   add a2 to b2
//   ...
//   repeat the sequence back for next 4 dataunits
//
//   variable A = XMM6 and variable B = XMM7.
//   (a1 = lower 8 bytes of XMM6 and b1 = lower 8 bytes of XMM7)

// Assumptions
// 1. size_in_bytes is a multiple of 16.
// 2. srcmem and dstmem are 16 byte aligned.
// 3. size_in_bytes is less than 2^19 bytes.

// Assumption 3 ensures that there is no overflow when numbers are being
// added (we can remove this assumption by doing modulus with a prime
// number when it is just about to overflow but that would be a very costly
// exercise)

// Returns true if the checksums are equal.
bool AdlerChecksum::Equals(const AdlerChecksum &other) const {
  return ( (a1_ == other.a1_) && (a2_ == other.a2_) &&
           (b1_ == other.b1_) && (b2_ == other.b2_) );
}

// Returns string representation of the Adler checksum.
string AdlerChecksum::ToHexString() const {
  char buffer[128];
  snprintf(buffer, sizeof(buffer), "%llx%llx%llx%llx", a1_, a2_, b1_, b2_);
  return string(buffer);
}

// Sets components of the Adler checksum.
void AdlerChecksum::Set(uint64 a1, uint64 a2, uint64 b1, uint64 b2) {
  a1_ = a1;
  a2_ = a2;
  b1_ = b1;
  b2_ = b2;
}

// Calculates Adler checksum for supplied data.
bool CalculateAdlerChecksum(uint64 *data64, unsigned int size_in_bytes,
                            AdlerChecksum *checksum) {
  // Use this data wrapper to access memory with 64bit read/write.
  datacast_t data;
  unsigned int count = size_in_bytes / sizeof(data);

  if (count > (1U) << 19) {
    // Size is too large, must be strictly less than 512 KB.
    return false;
  }

  uint64 a1 = 1;
  uint64 a2 = 1;
  uint64 b1 = 0;
  uint64 b2 = 0;

  unsigned int i = 0;
  while (i < count) {
    // Process 64 bits at a time.
    data.l64 = data64[i];
    a1 = a1 + data.l32.l;
    b1 = b1 + a1;
    a1 = a1 + data.l32.h;
    b1 = b1 + a1;
    i++;

    data.l64 = data64[i];
    a2 = a2 + data.l32.l;
    b2 = b2 + a2;
    a2 = a2 + data.l32.h;
    b2 = b2 + a2;
    i++;
  }
  checksum->Set(a1, a2, b1, b2);
  return true;
}

// C implementation of Adler memory copy.
bool AdlerMemcpyC(uint64 *dstmem64, uint64 *srcmem64,
                  unsigned int size_in_bytes, AdlerChecksum *checksum) {
  // Use this data wrapper to access memory with 64bit read/write.
  datacast_t data;
  unsigned int count = size_in_bytes / sizeof(data);

  if (count > ((1U) << 19)) {
    // Size is too large, must be strictly less than 512 KB.
    return false;
  }

  uint64 a1 = 1;
  uint64 a2 = 1;
  uint64 b1 = 0;
  uint64 b2 = 0;

  unsigned int i = 0;
  while (i < count) {
    // Process 64 bits at a time.
    data.l64 = srcmem64[i];
    a1 = a1 + data.l32.l;
    b1 = b1 + a1;
    a1 = a1 + data.l32.h;
    b1 = b1 + a1;
    dstmem64[i] = data.l64;
    i++;

    data.l64 = srcmem64[i];
    a2 = a2 + data.l32.l;
    b2 = b2 + a2;
    a2 = a2 + data.l32.h;
    b2 = b2 + a2;
    dstmem64[i] = data.l64;
    i++;
  }
  checksum->Set(a1, a2, b1, b2);
  return true;
}

// C implementation of Adler memory copy with some float point ops,
// attempting to warm up the CPU.
bool AdlerMemcpyWarmC(uint64 *dstmem64, uint64 *srcmem64,
                      unsigned int size_in_bytes, AdlerChecksum *checksum) {
  // Use this data wrapper to access memory with 64bit read/write.
  datacast_t data;
  unsigned int count = size_in_bytes / sizeof(data);

  if (count > ((1U) << 19)) {
    // Size is too large, must be strictly less than 512 KB.
    return false;
  }

  uint64 a1 = 1;
  uint64 a2 = 1;
  uint64 b1 = 0;
  uint64 b2 = 0;

  double a = 2.0 * static_cast<double>(srcmem64[0]);
  double b = 5.0 * static_cast<double>(srcmem64[0]);
  double c = 7.0 * static_cast<double>(srcmem64[0]);
  double d = 9.0 * static_cast<double>(srcmem64[0]);

  unsigned int i = 0;
  while (i < count) {
    // Process 64 bits at a time.
    data.l64 = srcmem64[i];
    a1 = a1 + data.l32.l;
    b1 = b1 + a1;
    a1 = a1 + data.l32.h;
    b1 = b1 + a1;
    dstmem64[i] = data.l64;
    i++;

    // Warm cpu up.
    a = a * b;
    b = b + c;

    data.l64 = srcmem64[i];
    a2 = a2 + data.l32.l;
    b2 = b2 + a2;
    a2 = a2 + data.l32.h;
    b2 = b2 + a2;
    dstmem64[i] = data.l64;
    i++;

    // Warm cpu up.
    c = c * d;
    d = d + d;
  }

  // Warm cpu up.
  d = a + b + c + d;
  if (d == 1.0) {
    // Reference the result so that it can't be discarded by the compiler.
    printf("Log: This will probably never happen.\n");
  }

  checksum->Set(a1, a2, b1, b2);
  return true;
}

// x86_64 SSE2 assembly implementation of fast and stressful Adler memory copy.
bool AdlerMemcpyAsm(uint64 *dstmem64, uint64 *srcmem64,
                    unsigned int size_in_bytes, AdlerChecksum *checksum) {
// Use assembly implementation where supported.
#if defined(STRESSAPPTEST_CPU_X86_64) || defined(STRESSAPPTEST_CPU_I686)

// Pull a bit of tricky preprocessing to make the inline asm both
// 32 bit and 64 bit.
#ifdef STRESSAPPTEST_CPU_I686  // Instead of coding both, x86...
#define rAX "%%eax"
#define rCX "%%ecx"
#define rDX "%%edx"
#define rBX "%%ebx"
#define rSP "%%esp"
#define rBP "%%ebp"
#define rSI "%%esi"
#define rDI "%%edi"
#endif

#ifdef STRESSAPPTEST_CPU_X86_64  // ...and x64, we use rXX macros.
#define rAX "%%rax"
#define rCX "%%rcx"
#define rDX "%%rdx"
#define rBX "%%rbx"
#define rSP "%%rsp"
#define rBP "%%rbp"
#define rSI "%%rsi"
#define rDI "%%rdi"
#endif

  // Elements 0 to 3 are used for holding checksum terms a1, a2,
  // b1, b2 respectively. These elements are filled by asm code.
  // Elements 4 and 5 are used by asm code to for ANDing MMX data and removing
  // 2 words from each MMX register (A MMX reg has 4 words, by ANDing we are
  // setting word index 0 and word index 2 to zero).
  // Element 6 and 7 are used for setting a1 and a2 to 1.
  volatile uint64 checksum_arr[] __attribute__ ((aligned(16))) =
      {0, 0, 0, 0, 0x00000000ffffffffUL, 0x00000000ffffffffUL, 1, 1};

  if ((size_in_bytes >> 19) > 0) {
    // Size is too large. Must be less than 2^19 bytes = 512 KB.
    return false;
  }

  // Number of 32-bit words which are not added to a1/a2 in the main loop.
  uint32 remaining_words = (size_in_bytes % 48) / 4;

  // Since we are moving 48 bytes at a time number of iterations = total size/48
  // is value of counter.
  uint32 num_of_48_byte_units = size_in_bytes / 48;

  asm volatile (
      // Source address is in ESI (extended source index)
      // destination is in EDI (extended destination index)
      // and counter is already in ECX (extended counter
      // index).
      "cmp  $0, " rCX ";"   // Compare counter to zero.
      "jz END;"

      // XMM6 is initialized with 1 and XMM7 with 0.
      "prefetchnta  0(" rSI ");"
      "prefetchnta 64(" rSI ");"
      "movdqu   48(" rAX "), %%xmm6;"
      "xorps      %%xmm7, %%xmm7;"

      // Start of the loop which copies 48 bytes from source to dst each time.
      "TOP:\n"

      // Make 6 moves each of 16 bytes from srcmem to XMM registers.
      // We are using 2 words out of 4 words in each XMM register,
      // word index 0 and word index 2
      "movdqa   0(" rSI "), %%xmm0;"
      "movdqu   4(" rSI "), %%xmm1;"  // Be careful to use unaligned move here.
      "movdqa  16(" rSI "), %%xmm2;"
      "movdqu  20(" rSI "), %%xmm3;"
      "movdqa  32(" rSI "), %%xmm4;"
      "movdqu  36(" rSI "), %%xmm5;"

      // Move 3 * 16 bytes from XMM registers to dstmem.
      // Note: this copy must be performed before pinsrw instructions since
      // they will modify the XMM registers.
      "movntdq %%xmm0,  0(" rDI ");"
      "movntdq %%xmm2, 16(" rDI ");"
      "movntdq %%xmm4, 32(" rDI ");"

      // Sets the word[1] and word[3] of XMM0 to XMM5 to zero.
      "andps 32(" rAX "), %%xmm0;"
      "andps 32(" rAX "), %%xmm1;"
      "andps 32(" rAX "), %%xmm2;"
      "andps 32(" rAX "), %%xmm3;"
      "andps 32(" rAX "), %%xmm4;"
      "andps 32(" rAX "), %%xmm5;"

      // Add XMM0 to XMM6 and then add XMM6 to XMM7.
      // Repeat this for XMM1, ..., XMM5.
      // Overflow(for XMM7) can occur only if there are more
      // than 2^16 additions => more than 2^17 words => more than 2^19 bytes so
      // if size_in_bytes > 2^19 than overflow occurs.
      "paddq %%xmm0, %%xmm6;"
      "paddq %%xmm6, %%xmm7;"
      "paddq %%xmm1, %%xmm6;"
      "paddq %%xmm6, %%xmm7;"
      "paddq %%xmm2, %%xmm6;"
      "paddq %%xmm6, %%xmm7;"
      "paddq %%xmm3, %%xmm6;"
      "paddq %%xmm6, %%xmm7;"
      "paddq %%xmm4, %%xmm6;"
      "paddq %%xmm6, %%xmm7;"
      "paddq %%xmm5, %%xmm6;"
      "paddq %%xmm6, %%xmm7;"

      // Increment ESI and EDI by 48 bytes and decrement counter by 1.
      "add $48, " rSI ";"
      "add $48, " rDI ";"
      "prefetchnta  0(" rSI ");"
      "prefetchnta 64(" rSI ");"
      "dec " rCX ";"
      "jnz TOP;"

      // Now only remaining_words 32-bit words are left.
      // make a loop, add first two words to a1 and next two to a2 (just like
      // above loop, the only extra thing we are doing is rechecking
      // rDX (=remaining_words) everytime we add a number to a1/a2.
      "REM_IS_STILL_NOT_ZERO:\n"
      // Unless remaining_words becomes less than 4 words(16 bytes)
      // there is not much issue and remaining_words will always
      // be a multiple of four by assumption.
      "cmp $4, " rDX ";"
      // In case for some weird reasons if remaining_words becomes
      // less than 4 but not zero then also break the code and go off to END.
      "jl END;"
      // Otherwise just go on and copy data in chunks of 4-words at a time till
      // whole data (<48 bytes) is copied.
      "movdqa  0(" rSI "), %%xmm0;"    // Copy next 4-words to XMM0 and to XMM1.

      "movdqa  0(" rSI "), %%xmm5;"    // Accomplish movdqu 4(%rSI) without
      "pshufd $0x39, %%xmm5, %%xmm1;"  // indexing off memory boundary.

      "movntdq %%xmm0,  0(" rDI ");"   // Copy 4-words to destination.
      "andps  32(" rAX "), %%xmm0;"
      "andps  32(" rAX "), %%xmm1;"
      "paddq     %%xmm0, %%xmm6;"
      "paddq     %%xmm6, %%xmm7;"
      "paddq     %%xmm1, %%xmm6;"
      "paddq     %%xmm6, %%xmm7;"
      "add $16, " rSI ";"
      "add $16, " rDI ";"
      "sub $4, " rDX ";"
      // Decrement %rDX by 4 since %rDX is number of 32-bit
      // words left after considering all 48-byte units.
      "jmp REM_IS_STILL_NOT_ZERO;"

      "END:\n"
      // Report checksum values A and B (both right now are two concatenated
      // 64 bit numbers and have to be converted to 64 bit numbers)
      // seems like Adler128 (since size of each part is 4 byte rather than
      // 1 byte).
      "movdqa %%xmm6,   0(" rAX ");"
      "movdqa %%xmm7,  16(" rAX ");"
      "sfence;"

      // No output registers.
      :
      // Input registers.
      : "S" (srcmem64), "D" (dstmem64), "a" (checksum_arr),
        "c" (num_of_48_byte_units), "d" (remaining_words)
  );  // asm.

  if (checksum != NULL) {
    checksum->Set(checksum_arr[0], checksum_arr[1],
                  checksum_arr[2], checksum_arr[3]);
  }

  // Everything went fine, so return true (this does not mean
  // that there is no problem with memory this just mean that data was copied
  // from src to dst and checksum was calculated successfully).
  return true;
#else
  // Fall back to C implementation for anything else.
  return AdlerMemcpyWarmC(dstmem64, srcmem64, size_in_bytes, checksum);
#endif
}
