
#include "config.h"
#include "types.h"
#include "debug.h"
#include "alloc-inl.h"
#include "hash.h"

#ifndef _HAVE_AFL_RUN_H
#define _HAVE_AFL_RUN_H

#define AREP4(_sym) (_sym), (_sym), (_sym), (_sym)
#define AREP8(_sym) AREP4(_sym), AREP4(_sym)
#define AREP16(_sym) AREP8(_sym), AREP8(_sym)
#define AREP32(_sym) AREP16(_sym), AREP16(_sym)
#define AREP64(_sym) AREP32(_sym), AREP32(_sym)
#define AREP128(_sym) AREP64(_sym), AREP64(_sym)

/* Execution status fault codes */

extern u32 exec_tmout;         /* Configurable exec timeout (ms)   */
extern u64 mem_limit;          /* Memory cap for child (MB)        */

volatile u8 child_timed_out,   /* Traced process timed out?        */
            stop_soon;         /* Ctrl-C pressed?                  */

enum {
  FAULT_NONE,
  FAULT_HANG,
  FAULT_CRASH,
  FAULT_ERROR,
  FAULT_NOINST,
  FAULT_NOBITS
};

u8  *out_file,                  /* File to fuzz, if any             */
    *doc_path;                  /* Path to documentation dir        */

u8  dumb_mode,                 /* Run in non-instrumented mode?    */
    showmap_mode,              /* Run on afl-showmap               */
    uses_asan,                 /* Target uses ASAN?                */
    kill_signal,               /* Signal that killed the child     */
    no_forkserver,             /* Disable forkserver?              */
    *target_path;              /* Path to target binary            */

u8  *in_bitmap;                /* Input bitmap                     */

u8  virgin_bits[MAP_SIZE],     /* Regions yet untouched by fuzzing */
    virgin_hang[MAP_SIZE],     /* Bits we haven't seen in hangs    */
    virgin_crash[MAP_SIZE];    /* Bits we haven't seen in crashes  */

u8* trace_bits;                /* SHM with instrumentation bitmap  */

s32 out_fd,                    /* Persistent fd for out_file       */
    dev_urandom_fd,            /* Persistent fd for /dev/urandom   */
    dev_null_fd;               /* Persistent fd for /dev/null      */

s32 shm_id;                    /* ID of the SHM region             */
s32 fsrv_ctl_fd;               /* Fork server control pipe (write) */
s32 fsrv_st_fd;                /* Fork server status pipe (read)   */

s32 forksrv_pid;               /* PID of the fork server           */
extern s32 child_pid;          /* PID of the fuzzed program        */

u64 total_execs;               /* Total execve() calls             */

u8* DMS(u64 val);
void remove_shm(void);
void setup_shm(void);
void classify_counts(u64* mem);
void init_forkserver(char** argv);
u8 run_target(char** argv);

#endif
