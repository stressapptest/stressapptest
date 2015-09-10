# Theory #

## Transactions per second ##

The simplest strategy that Stressful Application Test (or stressapptest) uses for memory testing, is that given a naive probability of P that any memory transaction fails, an effective test should maximize the number of potentially failing transactions per unit of time in order to see the greatest number of failures.

## Randomized transactions ##

Given the untestably large space of sequences of transactions, and the possibility that some unknown sequence of transactions may result in an error, stressapptest attempts to create a randomized variety of transactions. It is intended that most sequences of memory access should be unique, even in an arbitrarily long run of stressapptest. Each transaction is a randomized combination of data pattern and address, with the previous and following transactions split between sequential transactions of the same data pattern, and randomized data pattern and address on the same bus.

This is achieved by having many threads of execution sequentially accessing random locations in memory. This interleaving should cause the memory bus to receive a large variety or transaction sequences. This results in randomized address line testing, and a large variety of bank/row switching.

This is limited by several factors. Memory regions used by Linux and applications cannot be used. All accesses are cacheline sized, thus all memory transactions are 64 byte bursts. Only a few stressful data patterns are used, so the data content of these transactions is often similar.

## Data Patterns ##

SSO (simultaneous switching output) patterns have long been a mainstay of interface testing. These patterns are designed to cause the signal lines to rapidly switch between 1 and 0, which will draw the maximum amount of power and cause maximal noise on the nearby voltage rails. Noise on voltage rails and coupling with other nearby lines is likely to cause signalling problems on marginal lines. Also, given a probability of any signal level transition failing, SSO based patterns have the most transitions per period of time, and are thus more likely to exhibit a failure.

Some examples:
  * 0xffff, 0x0000  Pure SS0
  * 0x5555, 0xaaaa  Checkerboard
  * 0x0010, 0xffef  Inverted bit

## Stress testing ##

stressapptest performs many transactions in a short period of time, which can trigger problems related to system stress. Potential failures might be hardware queues filling or getting jammed, thermal issues, power issues, deadlock issues, starvation issues, coherency issues, etc.