## Executing Stressful application test ##

To execute, just type

```
stressapptest
```

on a shell and it will start executing with the default parameters. This usually is not enough for a regular test, so you may want to pass some command line arguments in order to get a real test.

## Command line arguments ##

You can control the behavior of stressapptest just passing command-line arguments. Here is a list of the most common arguments (default arguments in parentheses):

### General arguments ###

  * `-M mbytes` : megabytes of ram to test `(auto-detect all memory available)`
  * `-s seconds` : number of seconds to run `(20)`
  * `-m threads` : number of memory copy threads to run `(auto-detect to number of CPUs)`
  * `-i threads` : number of memory invert threads to run `(0)`
  * `-C threads` : number of memory CPU stress threads to run `(0)`
  * `--paddr_base` : allocate memory starting from this address `(0, currently no support for none-0)`
  * `-W` : Use more CPU-stressful memory copy `(false)`
  * `-A` : run in degraded mode on incompatible systems`(off)`
  * `-p pagesize` : size in bytes of memory chunks `(1024LL*1024LL)`
  * `-n ipaddr` : add a network thread connecting to system at 'ipaddr'. `(none)`
  * `--listen` : run a thread to listen for and respond to network threads. `(0)`

### Error handling ###

  * `-l logfile` : log output to file 'logfile' `(none)`
  * `--max_errors n` : exit early after finding 'n' errors `(off)`
  * `-v level` : verbosity (0-20) `(default: 8)`
  * `--no_errors` : run without checking for errors. `(off)`
  * `--force_errors` : inject false errors to test error handling. `(off)`
  * `--force_errors_like_crazy` : inject a lot of false errors to test error handling. `(off)`
  * `-F` : don't result check each transaction. `(false)`
  * `--stop_on_errors` : Stop after finding the first error. `(off)`

### Disk testing ###

  * `-d device` : add a direct write disk thread with block device (or file) 'device' `(0)`
  * `--findfiles` : find locations to do disk IO automatically `(false)`
  * `-f filename` : add a disk thread with tempfile 'filename' `(none)`
  * `--filesize size` : size of disk I/O tempfiles `(8mb)`
  * `--read-block-size` : size of block for reading `(512)`
  * `--write-block-size` :  size of block for writing. `(assume read-block-size if not defined)`
  * `--segment-size` : size of segments to split disk into. `(1)`
  * `--cache-size` : size of disk cache. `(16mb)`
  * `--blocks-per-segment` : number of blocks to read/write per segment per iteration. `(32)`
  * `--read-threshold` : maximum time(in us) a block read should take. `(100000 usec)`
  * `--write-threshold` : maximum time(in us) a block write should take. `(100000 usec)`
  * `--random-threads` :  number of random threads for each disk write thread. `(0)`
  * `--destructive` : write/wipe disk partition. `(off)`

### Cache coherency test ###

  * `--cc_test` : do the cache coherency testing `(off)`
  * `--cc_inc_count` : number of times to increment the cacheline's member `(1000)`
  * `--cc_line_count` : number of cache line sized data structures to allocate for the cache coherency threads to operate `(2)`

### Power spike control ###

  * `--pause_delay` : delay (in seconds) between power spikes `(600)`
  * `--pause_duration` : duration (in seconds) of each pause `(15)`

### NUMA control ###

  * `--local_numa` :  choose memory regions associated with each CPU to be tested by that CPU `(off)`
  * `--remote_numa` : choose memory regions not associated with each CPU to be tested by that CPU `(off)`

### Example command lines ###

  * ./stressapptest -s 20 -M 256 -m 8 -C 8 -W  # Allocate 256MB of memory and run 8 "warm copy" threads, and 8 cpu load threads. Exit after 20 seconds.
  * ./stressapptest -f /tmp/file1 -f /tmp/file2  # Run 2 file IO threads, and autodetect memory size and core count to select allocated memory and memory copy threads.