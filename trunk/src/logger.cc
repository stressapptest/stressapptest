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

#include "logger.h"

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include <string>
#include <vector>

// This file must work with autoconf on its public version,
// so these includes are correct.
#include "sattypes.h"


Logger *Logger::GlobalLogger() {
  static Logger logger;
  return &logger;
}

void Logger::VLogF(int priority, const char *format, va_list args) {
  if (priority > verbosity_) {
    return;
  }
  char buffer[4096];
  int length = vsnprintf(buffer, sizeof buffer, format, args);
  if (static_cast<size_t>(length) >= sizeof buffer) {
    length = sizeof buffer;
    buffer[sizeof buffer - 1] = '\n';
  }
  QueueLogLine(new string(buffer, length));
}

void Logger::StartThread() {
  LOGGER_ASSERT(!thread_running_);
  thread_running_ = true;
  LOGGER_ASSERT(0 == pthread_create(&thread_, NULL, &StartRoutine, this));
}

void Logger::StopThread() {
  LOGGER_ASSERT(thread_running_);
  thread_running_ = false;
  LOGGER_ASSERT(0 == pthread_mutex_lock(&queued_lines_mutex_));
  bool need_cond_signal = queued_lines_.empty();
  queued_lines_.push_back(NULL);
  LOGGER_ASSERT(0 == pthread_mutex_unlock(&queued_lines_mutex_));
  if (need_cond_signal) {
    LOGGER_ASSERT(0 == pthread_cond_signal(&queued_lines_cond_));
  }
  LOGGER_ASSERT(0 == pthread_join(thread_, NULL));
}

Logger::Logger() : verbosity_(20), log_fd_(-1), thread_running_(false) {
  LOGGER_ASSERT(0 == pthread_mutex_init(&queued_lines_mutex_, NULL));
  LOGGER_ASSERT(0 == pthread_cond_init(&queued_lines_cond_, NULL));
  LOGGER_ASSERT(0 == pthread_cond_init(&full_queue_cond_, NULL));
}

Logger::~Logger() {
  LOGGER_ASSERT(0 == pthread_mutex_destroy(&queued_lines_mutex_));
  LOGGER_ASSERT(0 == pthread_cond_destroy(&queued_lines_cond_));
  LOGGER_ASSERT(0 == pthread_cond_destroy(&full_queue_cond_));
}

void Logger::QueueLogLine(string *line) {
  LOGGER_ASSERT(line != NULL);
  LOGGER_ASSERT(0 == pthread_mutex_lock(&queued_lines_mutex_));
  if (thread_running_) {
    if (queued_lines_.size() >= kMaxQueueSize) {
      LOGGER_ASSERT(0 == pthread_cond_wait(&full_queue_cond_,
                                           &queued_lines_mutex_));
    }
    if (queued_lines_.empty()) {
      LOGGER_ASSERT(0 == pthread_cond_signal(&queued_lines_cond_));
    }
    queued_lines_.push_back(line);
  } else {
    WriteAndDeleteLogLine(line);
  }
  LOGGER_ASSERT(0 == pthread_mutex_unlock(&queued_lines_mutex_));
}

namespace {
void WriteToFile(const string& line, int fd) {
  LOGGER_ASSERT(write(fd, line.data(), line.size()) ==
                static_cast<ssize_t>(line.size()));
}
}

void Logger::WriteAndDeleteLogLine(string *line) {
  LOGGER_ASSERT(line != NULL);
  if (log_fd_ >= 0) {
    WriteToFile(*line, log_fd_);
  }
  WriteToFile(*line, 1);
  delete line;
}

void *Logger::StartRoutine(void *ptr) {
  Logger *self = static_cast<Logger*>(ptr);
  self->ThreadMain();
  return NULL;
}

void Logger::ThreadMain() {
  vector<string*> local_queue;
  LOGGER_ASSERT(0 == pthread_mutex_lock(&queued_lines_mutex_));

  for (;;) {
    if (queued_lines_.empty()) {
      LOGGER_ASSERT(0 == pthread_cond_wait(&queued_lines_cond_,
                                           &queued_lines_mutex_));
      continue;
    }

    // We move the log lines into a local queue so we can release the lock
    // while writing them to disk, preventing other threads from blocking on
    // our writes.
    local_queue.swap(queued_lines_);
    if (local_queue.size() >= kMaxQueueSize) {
      LOGGER_ASSERT(0 == pthread_cond_broadcast(&full_queue_cond_));
    }

    // Unlock while we process our local queue.
    LOGGER_ASSERT(0 == pthread_mutex_unlock(&queued_lines_mutex_));
    for (vector<string*>::const_iterator it = local_queue.begin();
         it != local_queue.end(); ++it) {
      if (*it == NULL) {
        // NULL is guaranteed to be at the end.
        return;
      }
      WriteAndDeleteLogLine(*it);
    }
    local_queue.clear();
    // We must hold the lock at the start of each iteration of this for loop.
    LOGGER_ASSERT(0 == pthread_mutex_lock(&queued_lines_mutex_));
  }
}
