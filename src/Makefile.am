bin_PROGRAMS = stressapptest

AM_DEFAULT_SOURCE_EXT=.cc

MAINFILES = main.cc
CFILES = os.cc
CFILES += os_factory.cc
CFILES += pattern.cc
CFILES += queue.cc
CFILES += sat.cc
CFILES += sat_factory.cc
CFILES += worker.cc
CFILES += finelock_queue.cc
CFILES += error_diag.cc
CFILES += disk_blocks.cc
CFILES += adler32memcpy.cc
CFILES += logger.cc

HFILES = os.h
HFILES += pattern.h
HFILES += queue.h
HFILES += sat.h
HFILES += worker.h
HFILES += sattypes.h
HFILES += finelock_queue.h
HFILES += error_diag.h
HFILES += disk_blocks.h
HFILES += adler32memcpy.h
HFILES += logger.h

stressapptest_SOURCES = $(MAINFILES) $(CFILES) $(HFILES)
