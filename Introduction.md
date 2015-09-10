## Objective ##

Stressful Application Test (or stressapptest) tries to maximize randomized traffic to memory from processor and I/O, with the intent of creating a realistic high load situation

stressapptest may be used for various purposes:
  * Stress test: as described here.
  * Hardware qualification and debugging.
  * Memory interface test: see the [Theory](Theory.md) behind this.
  * Disk testing.

## Background ##

Many hardware issues reproduce infrequently, or only under corner cases. The theory being used here is that by maximizing bus and memory traffic, the number of transactions is increased, and therefore the probability of failing a transaction is increased.

## Overview ##

stressapptest is a userspace test, primarily composed of threads doing memory copies and directIO disk read/write. It allocates a large block of memory (typically 85% of the total memory on the machine), and each thread will choose randomized blocks of memory to copy, or to write to disk. Typically there are two threads per processor, and two threads for each disk. Result checking is done as the test proceeds by CRCing the data as it is copied.

## Downloading it ##

stressapptest can be download through svn at
```
svn checkout http://stressapptest.googlecode.com/svn/trunk/ stressapptest
```
(tgz downloads are no longer supported by code.google.com)

## How to Install ##

check the [Installation Guide](InstallationGuide.md)

## How to Run ##

check the [User Guide](UserGuide.md)

## Detailed Design ##

The code is structured fairly simply:
  * A large amount of memory is allocated in a single block (default is 85% of physical memory size).
  * Memory is divided into chunks, each filled with a potentially stressful data pattern.
  * Worker threads are spawned, which draw pages from an "empty" queue and a "valid" queue, and copy the data from one block to the other.
    * Some threads memory copy the data.
    * Some threads invert the data in place.
    * Some threads write the data to disk, and read it to the new location.
  * After the specified time has elapsed, all "valid" pages have their data compared with the original fill pattern.

## Caveats ##

This test works by stressing system interfaces. It is good at catching memory signal integrity or setup and hold problems, memory controller and bus interface issues, and disk controller issues. It is moderately good at catching bad memory cells and cache coherency issues. It is not good at catching bad processors, bad physical media on disks, or problems that require periods of inactivity to manifest themselves. It is not a thorough test of OS internals. The test may cause marginal systems to become bricks if disk or memory errors cause hard drive corruption, or if the physical components overheat.

## Security Considerations ##

Someone running stressapptest on a live system could cause other applications to become extremely slow or unresponsive.

## Logged information ##

stressapptest can output a logfile of miscompares detected during its execution. stressapptest cannot yet log reboot failures, or other failures not visible to user space.