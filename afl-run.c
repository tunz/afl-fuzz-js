/*
   american fuzzy lop - fuzzer code
   --------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Forkserver design by Jann Horn <jannhorn@googlemail.com>

   Copyright 2013, 2014, 2015 Google Inc. All rights reserved.

   Speed improvement using ptrace by Choongwoo Han <cwhan.tunz@gmail.com>

   Copyright 2015 Naver Corp.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This is the real deal: the program takes an instrumented binary and
   attempts a variety of basic fuzzing tricks, paying close attention to
   how they affect the execution path.

 */


#include "afl-run.h"

#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/shm.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdio.h>
#include <errno.h>
#include <sys/personality.h>

#define AFL_RUN

static void *start_address = 0;

/* Describe integer as memory size. */

u8* DMS(u64 val) {

  static u8 tmp[12][16];
  static u8 cur;

  cur = (cur + 1) % 12;

#define CHK_FORMAT(_divisor, _limit_mult, _fmt, _cast) do { \
    if (val < (_divisor) * (_limit_mult)) { \
      sprintf(tmp[cur], _fmt, ((_cast)val) / (_divisor)); \
      return tmp[cur]; \
    } \
  } while (0)

  /* 0-9999 */
  CHK_FORMAT(1, 10000, "%llu B", u64);

  /* 10.0k - 99.9k */
  CHK_FORMAT(1024, 99.95, "%0.01f kB", double);

  /* 100k - 999k */
  CHK_FORMAT(1024, 1000, "%llu kB", u64);

  /* 1.00M - 9.99M */
  CHK_FORMAT(1024 * 1024, 9.995, "%0.02f MB", double);

  /* 10.0M - 99.9M */
  CHK_FORMAT(1024 * 1024, 99.95, "%0.01f MB", double);

  /* 100M - 999M */
  CHK_FORMAT(1024 * 1024, 1000, "%llu MB", u64);

  /* 1.00G - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024, 9.995, "%0.02f GB", double);

  /* 10.0G - 99.9G */
  CHK_FORMAT(1024LL * 1024 * 1024, 99.95, "%0.01f GB", double);

  /* 100G - 999G */
  CHK_FORMAT(1024LL * 1024 * 1024, 1000, "%llu GB", u64);

  /* 1.00T - 9.99G */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 9.995, "%0.02f TB", double);

  /* 10.0T - 99.9T */
  CHK_FORMAT(1024LL * 1024 * 1024 * 1024, 99.95, "%0.01f TB", double);

#undef CHK_FORMAT

  /* 100T+ */
  strcpy(tmp[cur], "infty");
  return tmp[cur];

}


/* Describe time delta. Returns one static buffer, 34 chars of less. */


/* Destructively classify execution counts in a trace. This is used as a
   preprocessing step for any newly acquired traces. Called on every exec,
   must be fast. */

static u8 count_class_lookup[256] = {

  /* 0 - 3:       4 */ 0, 1, 2, 4,
  /* 4 - 7:      +4 */ AREP4(8),
  /* 8 - 15:     +8 */ AREP8(16),
  /* 16 - 31:   +16 */ AREP16(32),
  /* 32 - 127:  +96 */ AREP64(64), AREP32(64),
  /* 128+:     +128 */ AREP128(128)

};

#ifdef __x86_64__

void classify_counts(u64* mem) {

  u32 i = MAP_SIZE >> 3;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = count_class_lookup[mem8[0]];
      mem8[1] = count_class_lookup[mem8[1]];
      mem8[2] = count_class_lookup[mem8[2]];
      mem8[3] = count_class_lookup[mem8[3]];
      mem8[4] = count_class_lookup[mem8[4]];
      mem8[5] = count_class_lookup[mem8[5]];
      mem8[6] = count_class_lookup[mem8[6]];
      mem8[7] = count_class_lookup[mem8[7]];

    }

    mem++;

  }

}

#else

static void classify_counts(u32* mem) {

  u32 i = MAP_SIZE >> 2;

  while (i--) {

    /* Optimize for sparse bitmaps. */

    if (*mem) {

      u8* mem8 = (u8*)mem;

      mem8[0] = count_class_lookup[mem8[0]];
      mem8[1] = count_class_lookup[mem8[1]];
      mem8[2] = count_class_lookup[mem8[2]];
      mem8[3] = count_class_lookup[mem8[3]];

    }

    mem++;

  }

}

#endif /* ^__x86_64__ */



/* Get rid of shared memory (atexit handler). */

void remove_shm(void) {

  shmctl(shm_id, IPC_RMID, NULL);

}

/* Configure shared memory and virgin_bits. This is called at startup. */

void setup_shm(void) {

  u8* shm_str;

  if (!in_bitmap) memset(virgin_bits, 255, MAP_SIZE);

  memset(virgin_hang, 255, MAP_SIZE);
  memset(virgin_crash, 255, MAP_SIZE);

  shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

  if (shm_id < 0) PFATAL("shmget() failed");

  atexit(remove_shm);

  shm_str = alloc_printf("%d", shm_id);

  /* If somebody is asking us to fuzz instrumented binaries in dumb mode,
     we don't want them to detect instrumentation, since we won't be sending
     fork server commands. This should be replaced with better auto-detection
     later on, perhaps? */

  if (!dumb_mode)
    setenv(SHM_ENV_VAR, shm_str, 1);

  ck_free(shm_str);

  trace_bits = shmat(shm_id, NULL, 0);
  
  if (!trace_bits) PFATAL("shmat() failed");

}

ssize_t long_read(int fd, void* buf, size_t count)
{
  static struct itimerval it;
  s32 rlen;

  /* Wait for the fork server to come up, but don't wait too long. */

  it.it_value.tv_sec = ((exec_tmout * FORK_WAIT_MULT) / 1000);
  it.it_value.tv_usec = ((exec_tmout * FORK_WAIT_MULT) % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  rlen = read(fd, buf, count);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  return rlen;
}

int wait_for_syscall(pid_t p) {
  int status;
  long pc;

  while (1) {

    if (stop_soon)
      return 1;

    ptrace(PTRACE_SYSCALL, p, 0, 0);
    waitpid(p, &status, 0);

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSEGV)
    {
#ifdef __x86_64__
      pc = ptrace(PTRACE_PEEKUSER, forksrv_pid, __builtin_offsetof(struct user, regs.rip));
#else
      pc = ptrace(PTRACE_PEEKUSER, forksrv_pid, __builtin_offsetof(struct user, regs.eip));
#endif
      FATAL("Crash before read first input. : %p", (void *)pc);
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
      return 0;

    if (WIFEXITED(status))
      return 1;
  }
}

/* Spin up fork server (instrumented mode only). The idea is explained here:

   http://lcamtuf.blogspot.com/2014/10/fuzzing-binaries-without-execve.html

   In essence, the instrumentation allows us to skip execve(), and just keep
   cloning a stopped child. So, we just execute once, and then send commands
   through a pipe. The other part of this logic is in afl-as.h. */

void init_forkserver(char** argv) {

  int st_pipe[2], ctl_pipe[2];
  int status;
  s32 rlen;

  ACTF("Spinning up the fork server...");

  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();

  if (forksrv_pid < 0) PFATAL("fork() failed");

  if (!forksrv_pid) {

    struct rlimit r;

    /* Disable ASLR */
#ifdef __x86__64__
    syscall(SYS_personality, ADDR_NO_RANDOMIZE | PER_LINUX);
#else
    syscall(SYS_personality, ADDR_NO_RANDOMIZE | PER_LINUX32);
#endif

    /* Umpf. On OpenBSD, the default fd limit for root users is set to
       soft 128. Let's try to fix that... */

    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */

    }

    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

      /* This takes care of OpenBSD, which doesn't have RLIMIT_AS, but
         according to reliable sources, RLIMIT_DATA covers anonymous
         maps - so we should be getting good protection against OOM bugs. */

      setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */


    }

    /* Dumping cores is slow and can lead to anomalies if SIGKILL is delivered
       before the dump is complete. */

    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

    /* Isolate the process and configure standard descriptors. If out_file is
       specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

    setsid();

    if (!showmap_mode) {

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {
 
        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);
      }

      close(dev_null_fd);
    }

    /* Set up control and status pipes, close the unneeded original fds. */

    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);

    /* This should improve performance a bit, since it stops the linker from
       doing extra work post-fork(). */

    setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */

    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "msan_track_origins=0", 0);
    execv(target_path, argv);

    /* Use a distinctive return value to tell the parent about execv()
       falling through. This is hackish, but meh... */

    exit(EXEC_FAIL);

  }

  /* Close the unneeded endpoints. */

  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];

  rlen = long_read(fsrv_st_fd, &status, 4);

  if (write(fsrv_ctl_fd, &start_address, status) < status) 
    FATAL("Incomplete sending start address.");

  if (start_address == 0) {
    /* If we don't find first read yet. */

    int syscall;

    ACTF("Finding start point."); 

    waitpid(forksrv_pid, &status, 0);
    ptrace(PTRACE_SETOPTIONS, forksrv_pid, 0, PTRACE_O_TRACESYSGOOD);

    while(1) {
      if (wait_for_syscall(forksrv_pid))
        FATAL("Program dead before read first input.");

#ifdef __x86_64__
      syscall = ptrace(PTRACE_PEEKUSER, forksrv_pid, 
		      __builtin_offsetof(struct user, regs.orig_rax));
#else
      syscall = ptrace(PTRACE_PEEKUSER, forksrv_pid, 
		      __builtin_offsetof(struct user, regs.orig_eax));
#endif

      if ((!out_file && syscall == SYS_read) || 
	   (out_file && syscall == SYS_open)) {

	int correct_location = 1;

	if (out_file) {

          u8* cwd = getcwd(NULL, 0);
	  u8* out_file_fullpath;
	  u8* open_fname = ck_alloc(1024);
	  unsigned long fname_addr, tmp;
	  int read_byte=0;

          if (out_file[0] == '/') out_file_fullpath = out_file;
          else out_file_fullpath = alloc_printf("%s/%s", cwd, out_file);
	  
#ifdef __x86_64__
          fname_addr = ptrace(PTRACE_PEEKUSER, forksrv_pid, 
		      __builtin_offsetof(struct user, regs.rdi));
#else
          fname_addr = ptrace(PTRACE_PEEKUSER, forksrv_pid, 
		      __builtin_offsetof(struct user, regs.ebx));
#endif
	  /* Read filename opened by child */
          while (1) {

            if (read_byte + sizeof(tmp)> 1024)
              break;

            tmp = ptrace(PTRACE_PEEKDATA, forksrv_pid, fname_addr + read_byte);
            if(errno != 0) {
              open_fname[read_byte] = 0;
              break;
            }

            memcpy(open_fname + read_byte, &tmp, sizeof tmp);
            if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
              break;
            read_byte += sizeof(tmp);
          }

	  if (strcmp(open_fname, out_file_fullpath) != 0)
            correct_location = 0;


          if (out_file[0] != '/') ck_free(out_file_fullpath);
	  ck_free(open_fname);
	}

	if (correct_location) {

          start_address = *((void **)trace_bits);

	  ACTF("Start address found: %p",start_address); 

          if (start_address)
            memset(trace_bits, 0, 
	  	 MAP_SIZE < sizeof(void *) ? MAP_SIZE : sizeof(void *));
	  else
            FATAL("Fail to find start address");

          /* kill current child, and restart with known start address. */
	  kill(forksrv_pid, SIGKILL);
          waitpid(forksrv_pid, &status, WUNTRACED);
	  return init_forkserver(argv);
	}
      }

      //if (wait_for_syscall(forksrv_pid))
      //  FATAL("Program dead before read first input.");
    }
  } else {
    /* Check if fork server set. */

    rlen = long_read(fsrv_st_fd, &status, 4);

    if (rlen == 4) {
      OKF("All right - fork server is up.");
      return;
    }
  }

  if (child_timed_out)
    FATAL("Timeout while initializing fork server (adjusting -t may help)");

  if (waitpid(forksrv_pid, &status, WUNTRACED) <= 0)
    PFATAL("waitpid() failed");

  if (WIFSIGNALED(status)) {

    if (mem_limit && mem_limit < 500 && uses_asan) {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! Since it seems to be built with ASAN and you have a\n"
           "    restrictive memory limit configured, this is expected; please read\n"
           "    %s/notes_for_asan.txt for help.\n", doc_path);

    } else {

      SAYF("\n" cLRD "[-] " cRST
           "Whoops, the target binary crashed suddenly, before receiving any input\n"
           "    from the fuzzer! There are several probable explanations:\n\n"

           "    - The current memory limit (%s) is too restrictive, causing the\n"
           "      target to hit an OOM condition in the dynamic linker. Try bumping up\n"
           "      the limit with the -m setting in the command line. A simple way confirm\n"
           "      this diagnosis would be:\n\n"

#ifdef RLIMIT_AS
           "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
           "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

           "    - The binary is just buggy and explodes entirely on its own. If so, you\n"
           "      need to fix the underlying problem or find a better replacement.\n\n"

#ifdef __APPLE__

           "    - On MacOS X, the semantics of fork() syscalls are non-standard and may\n"
           "      break afl-fuzz performance optimizations when running platform-specific\n"
           "      binaries. To fix this, set AFL_NO_FORKSRV=1 in the environment.\n\n"

#endif /* __APPLE__ */

           "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
           "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
           DMS(mem_limit << 20), mem_limit - 1);

    }

    FATAL("Fork server crashed with signal %d", WTERMSIG(status));

  }


  if (WEXITSTATUS(status) == EXEC_FAIL)
    FATAL("Unable to execute target application ('%s')", argv[0]);

  if (mem_limit && mem_limit < 500 && uses_asan) {

    SAYF("\n" cLRD "[-] " cRST
           "Hmm, looks like the target binary terminated before we could complete a\n"
           "    handshake with the injected code. Since it seems to be built with ASAN and\n"
           "    you have a restrictive memory limit configured, this is expected; please\n"
           "    read %s/notes_for_asan.txt for help.\n", doc_path);

  } else {

    SAYF("\n" cLRD "[-] " cRST
         "Hmm, looks like the target binary terminated before we could complete a\n"
         "    handshake with the injected code. There are two probable explanations:\n\n"

         "    - The current memory limit (%s) is too restrictive, causing an OOM\n"
         "      fault in the dynamic linker. This can be fixed with the -m option. A\n"
         "      simple way to confirm the diagnosis may be:\n\n"

#ifdef RLIMIT_AS
         "      ( ulimit -Sv $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#else
         "      ( ulimit -Sd $[%llu << 10]; /path/to/fuzzed_app )\n\n"
#endif /* ^RLIMIT_AS */

         "    - Less likely, there is a horrible bug in the fuzzer. If other options\n"
         "      fail, poke <lcamtuf@coredump.cx> for troubleshooting tips.\n",
         DMS(mem_limit << 20), mem_limit - 1);

  }

  FATAL("Fork server handshake failed");

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update trace_bits[]. */

u8 run_target(char** argv) {

  static struct itimerval it;
  int status = 0;

  child_timed_out = 0;

  memset(trace_bits, 0, MAP_SIZE);

  /* If we're running in "dumb" mode, we can't rely on the fork server
     logic compiled into the target program, so we will just keep calling
     execve(). There is a bit of code duplication between here and 
     init_forkserver(), but c'est la vie. */

  if (dumb_mode || no_forkserver) {

    child_pid = fork();

    if (child_pid < 0) PFATAL("fork() failed");

    if (!child_pid) {

      struct rlimit r;

      if (mem_limit) {

        r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

        setrlimit(RLIMIT_AS, &r); /* Ignore errors */

#else

        setrlimit(RLIMIT_DATA, &r); /* Ignore errors */

#endif /* ^RLIMIT_AS */

      }

      r.rlim_max = r.rlim_cur = 0;

      setrlimit(RLIMIT_CORE, &r); /* Ignore errors */

      /* Isolate the process and configure standard descriptors. If out_file is
         specified, stdin is /dev/null; otherwise, out_fd is cloned instead. */

      setsid();

      dup2(dev_null_fd, 1);
      dup2(dev_null_fd, 2);

      if (out_file) {

        dup2(dev_null_fd, 0);

      } else {

        dup2(out_fd, 0);
        close(out_fd);

      }

      close(dev_null_fd);

      /* Set sane defaults for ASAN if nothing else specified. */

      setenv("ASAN_OPTIONS", "abort_on_error=1:"
                             "detect_leaks=0:"
                             "allocator_may_return_null=1", 0);

      setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                             "msan_track_origins=0", 0);

      execv(target_path, argv);

      /* Use a distinctive return value to tell the parent about execv()
         falling through. */

      exit(EXEC_FAIL);

    }

  } else {

    s32 res;

    /* In non-dumb mode, we have the fork server up and running, so simply
       tell it to have at it, and then read back PID. */

    if (!forksrv_pid) init_forkserver(argv);

    if ((res = write(fsrv_ctl_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to request new process from fork server (OOM?)");

    }

    if (child_pid <= 0) FATAL("Fork server is misbehaving (OOM?)");

  }

  /* Configure timeout, as requested by user, then wait for child to terminate. */

  it.it_value.tv_sec = (exec_tmout / 1000);
  it.it_value.tv_usec = (exec_tmout % 1000) * 1000;

  setitimer(ITIMER_REAL, &it, NULL);

  /* The SIGALRM handler simply kills the child_pid and sets child_timed_out. */

  if (dumb_mode || no_forkserver) {

    if (waitpid(child_pid, &status, WUNTRACED) <= 0) PFATAL("waitpid() failed");

  } else {

    s32 res;

    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {

      if (stop_soon) return 0;
      RPFATAL(res, "Unable to communicate with fork server");

    }

  }

  child_pid = 0;
  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */

  total_execs++;

  /* Report outcome to caller. */

  if (child_timed_out) return FAULT_HANG;

  if (WIFSIGNALED(status) && !stop_soon) {
    kill_signal = WTERMSIG(status);
    return FAULT_CRASH;
  }

  /* A somewhat nasty hack for MSAN, which doesn't support abort_on_error and
     must use a special exit code. */

  if (uses_asan && WEXITSTATUS(status) == MSAN_ERROR) {
    kill_signal = 0;
    return FAULT_CRASH;
  }

  if ((dumb_mode || no_forkserver) && WEXITSTATUS(status) == EXEC_FAIL)
    return FAULT_ERROR;

  return FAULT_NONE;

}

