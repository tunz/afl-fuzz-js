/*
   american fuzzy lop - run program, display map
   ---------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2013, 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   A very simple tool that runs the targeted binary and displays
   the contents of the trace bitmap in a human-readable form. Useful in
   scripts to eliminate redundant inputs and perform other checks.

   If AFL_SINK_OUTPUT is set, output from the traced program will be
   redirected to /dev/null. AFL_QUIET inhibits all non-fatal messages
   from the tool, too.

 */

#define AFL_MAIN

#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "afl-run.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include <dirent.h>
#include <fcntl.h>

#include <sys/fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/resource.h>

u32 exec_tmout = EXEC_TIMEOUT;        /* Configurable exec timeout (ms)   */
u64 mem_limit = 4*1024L;            /* Memory cap for child (MB)        */
s32 child_pid = -1;                   /* PID of the fuzzed program        */

static u8  sink_output,               /* Sink program output               */
           be_quiet,                  /* Quiet mode (tuples & errors only) */
           minimize_mode;             /* Called from minimize_corpus.sh?   */

/* Show all recorded tuples. */

static inline void show_tuples(void) {

  u8* current = (u8*)trace_bits;
  u32 i;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  if (minimize_mode) {

    for (i = 0; i < MAP_SIZE; i++) {

      if (*current) SAYF("%u%u\n", *current, i);
      current++;

    }

  } else {

    for (i = 0; i < MAP_SIZE; i++) {

      if (*current) SAYF("%06u:%u\n", i, *current);

      current++;

    }

  }

}


/* See if any bytes are set in the bitmap. */

static inline u8 anything_set(void) {

  u32* ptr = (u32*)trace_bits;
  u32  i   = (MAP_SIZE >> 2);

  while (i--) if (*(ptr++)) return 1;

  return 0;

}

/* Handle stop signal (Ctrl-C, etc). */

static void handle_stop_sig(int sig) {

  stop_soon = 1; 

  if (child_pid > 0) kill(child_pid, SIGKILL);
  if (forksrv_pid > 0) kill(forksrv_pid, SIGKILL);

}

/* Set up signal handlers. More complicated that needs to be, because libc on
   Solaris doesn't resume interrupted reads(), sets SA_RESETHAND when you call
   siginterrupt(), and does other stupid things. */

static void setup_signal_handlers(void) {

  struct sigaction sa;

  sa.sa_handler   = NULL;
  sa.sa_flags     = SA_RESTART;
  sa.sa_sigaction = NULL;

  sigemptyset(&sa.sa_mask);

  /* Various ways of saying "stop". */

  sa.sa_handler = handle_stop_sig;
  sigaction(SIGHUP, &sa, NULL);
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);

  /* Things we don't care about. */

  sa.sa_handler = SIG_IGN;
  sigaction(SIGTSTP, &sa, NULL);
  sigaction(SIGPIPE, &sa, NULL);

}



/* Display usage hints. */

static void usage(u8* argv0) {

  SAYF("\n%s /path/to/traced_app [ ... ]\n\n"

       "Shows all instrumentation tuples recorded when executing a binary compiled\n"
       "with afl-gcc or afl-clang. You can set AFL_SINK_OUTPUT=1 to sink all output\n"
       "from the executed program, AFL_QUIET=1 to suppress non-fatal messages from\n"
       "this tool, or AFL_EDGES_ONLY to only display edges, not hit counts.\n\n",
       argv0);

  exit(1);

}


/* Main entry point */

int main(int argc, char** argv) {

  minimize_mode = !!getenv("AFL_MINIMIZE_MODE");

  if (!minimize_mode && !getenv("AFL_QUIET")) {

    SAYF(cCYA "afl-showmap " cBRI VERSION cRST " (" __DATE__ " " __TIME__ 
         ") by <lcamtuf@google.com>\n");

  } else be_quiet = 1;

  if (argc < 2) usage(argv[0]);

  setup_shm();
  setup_signal_handlers();

  if (minimize_mode || getenv("AFL_SINK_OUTPUT")) sink_output = 1;

  if (!be_quiet && !sink_output)
    SAYF("\n-- Program output begins --\n");  

  target_path = argv[1];
  showmap_mode = 1;
  run_target(argv + 1);

  if (!be_quiet && !sink_output)
    SAYF("-- Program output ends --\n");  

  if (!anything_set()) FATAL("No instrumentation data recorded");

  if (!be_quiet) SAYF(cBRI "\nTuples recorded:\n\n" cRST);

  show_tuples();

  exit(0);

}

