// Copyright 2009 Google Inc. All Rights Reserved.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//      http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef STRESSAPPTEST_LOGGER_H_
#define STRESSAPPTEST_LOGGER_H_

#include <pthread.h>
#include <stdarg.h>

#include <string>
#include <vector>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "sattypes.h"

// Attempts to log additional lines will block when the queue reaches this size.
// Due to how the logging thread works, up to twice this many log lines may be
// outstanding at any point.
static const size_t kMaxQueueSize = 250;


// This is only for use by the Logger class, do not use it elsewhere!
//
// All Logger assertions should use this macro instead of sat_assert().
//
// This is like sat_assert() from sattypes.h, but whereas sat_assert() tries to
// log the assertion after printing it to stderr, this only prints it to stderr.
// Logging from within the wrong part of the logger would trigger a deadlock,
// and even in places where it wouldn't there's a very good chance that the
// logger is in no condition to handle new log lines.
#define LOGGER_ASSERT(x) \
{\
  if (!(x)) {\
    fprintf(stderr, "Assertion failed at %s:%d\n", __FILE__, __LINE__);\
    exit(1);\
  }\
}


// This class handles logging in SAT.  It is a singleton accessed via
// GlobalLogger().
//
// By default log lines are written in the calling thread.  Call StartThread()
// to launch a dedicated thread for the writes.
class Logger {
 public:
  // Returns a pointer to the single global Logger instance.  Will not return
  // NULL.
  static Logger *GlobalLogger();

  // Lines with a priority numerically greater than this will not be logged.
  // May not be called while multiple threads are running.
  void SetVerbosity(int verbosity) {
    verbosity_ = verbosity;
  }

  // Sets a file to log to, in addition to stdout.  May not be called while
  // multiple threads are running.
  //
  // Args:
  //   log_fd: The file descriptor to write to.  Will not be closed by this
  //           object.
  void SetLogFd(int log_fd) {
    LOGGER_ASSERT(log_fd >= 0);
    log_fd_ = log_fd;
  }

  // Set output to be written to stdout only.  This is the default mode.  May
  // not be called while multiple threads are running.
  void SetStdoutOnly() {
    log_fd_ = -1;
  }

  // Logs a line, with a vprintf(3)-like interface.  This will block on writing
  // the line to stdout/disk iff the dedicated logging thread is not running.
  // This will block on adding the line to the queue if doing so would exceed
  // kMaxQueueSize.
  //
  // Args:
  //   priority: If this is numerically greater than the verbosity, the line
  //             will not be logged.
  //   format: see vprintf(3)
  //   args: see vprintf(3)
  void VLogF(int priority, const char *format, va_list args);

  // Starts the dedicated logging thread.  May not be called while multiple
  // threads are already running.
  void StartThread();

  // Stops the dedicated logging thread.  May only be called when the logging
  // thread is the only other thread running.  Any queued lines will be logged
  // before this returns.  Waits for the thread to finish before returning.
  void StopThread();

 private:
  Logger();

  ~Logger();

  // Args:
  //   line: Must be non-NULL.  This function takes ownership of it.
  void QueueLogLine(string *line);

  // Args:
  //   line: Must be non-NULL.  This function takes ownership of it.
  void WriteAndDeleteLogLine(string *line);

  // Callback for pthread_create(3).
  static void *StartRoutine(void *ptr);

  // Processes the log queue.
  void ThreadMain();

  pthread_t thread_;
  int verbosity_;
  int log_fd_;
  bool thread_running_;
  vector<string*> queued_lines_;
  // This doubles as a mutex for log_fd_ when the logging thread is not running.
  pthread_mutex_t queued_lines_mutex_;
  // Lets the logging thread know that the queue is no longer empty.
  pthread_cond_t queued_lines_cond_;
  // Lets the threads blocked on the queue having reached kMaxQueueSize know
  // that the queue has been emptied.
  pthread_cond_t full_queue_cond_;

  DISALLOW_COPY_AND_ASSIGN(Logger);
};

#endif  // STRESSAPPTEST_LOGGER_H_
