/*
  Copyright 2015 Google LLC All rights reserved.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/

/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   This code is the rewrite of afl-as.h's main_payload.
*/

#include "../android-ashmem.h"
#include "../config.h"
#include "../types.h"
#include "../alloc-inl.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

#include <fcntl.h>


/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 0
#endif /* ^USE_TRACE_PC */

// #define PREFUZZ_DATA_INST




/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

// #ifdef PREFUZZ_DATA_INST
u8  __afl_area_initial[SHM_SIZE];
// #else 
// u8  __afl_area_initial[MAP_SIZE];
// #endif

u8* __afl_area_ptr = __afl_area_initial;
u8* __afl_func_ptr = __afl_area_initial + MAP_SIZE;
u8* __afl_cmps_ptr = __afl_area_initial + MAP_SIZE + FUNC_SIZE;

__thread u32 __afl_prev_loc;


u8 sanitizer_reach[VMAP_COUNT],
   debug_edge[MAP_SIZE];

/* Running in persistent mode? */

static u8 is_persistent;

#ifdef PREFUZZ_DBG

FILE *dbg_bb, *dbg_cmp;

u8 __init_dbg_file() {
  // $TMP_DIR/visit_bbs.csv/visit_constraint.csv
  char *tmp_dir = getenv("TMP_DIR");
  char *dbg_bb_path = alloc_printf("%s/visit_bbs.csv", tmp_dir),
       *dbg_cmp_path = alloc_printf("%s/visit_constraint.csv", tmp_dir);
  
  // if (access(dbg_bb_path, F_OK) || access(dbg_cmp_path, F_OK)) 
  //   return -1;
  
  dbg_bb = fopen(dbg_bb_path, "a");
  dbg_cmp = fopen(dbg_cmp_path, "a");
  
  if (!dbg_bb || !dbg_cmp) return -1;
  return 0;
}

void __prefuzz_dbg_path(u32 prev_loc, u32 cur_loc) {
  if (dbg_bb)
    fprintf(dbg_bb, "%u, %u, %u\n", prev_loc, cur_loc, (prev_loc << 1) ^ cur_loc);
  else 
    PFATAL("failed open dbg_bb!\n");
}

void __prefuzz_dbg_cmp(u32 cur_loc) {
  if (dbg_cmp)
    fprintf(dbg_cmp, "%u\n", cur_loc);
  else 
    PFATAL("failed open dbg_cmp!\n");
}


/*
void __prefuzz_sanitizer_reach(u32 san_id) {
  printf("prefuzz alert : reach sanitizer %d\n", san_id);
  fflush(stdout);
}

void __prefuzz_sanitizer_trigger(u32 san_id) {
  printf("prefuzz alert : trigger sanitizer %d\n", san_id);
  fflush(stdout);
}
*/

void __prefuzz_update_log(void) {
  s32 fd;

  u8* fname = getenv("CMP_LOG_FILE");
  fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

  if (fd < 0) PFATAL("Unable to open '%s'", fname);
  write(fd, debug_edge, MAP_SIZE);
  write(fd, sanitizer_reach, VMAP_COUNT);

  close(fd);

}

void __prefuzz_sanitizer_reach(u32 san_id) {
  if (!sanitizer_reach[san_id]) {
    sanitizer_reach[san_id] = 1;
    __prefuzz_update_log();
  }
}

void __prefuzz_sanitizer_trigger(u32 san_id) {
  if (sanitizer_reach[san_id] != 2) {
    sanitizer_reach[san_id] = 2;
    __prefuzz_update_log();  
  }
}

void __prefuzz_log_edge(u32 edge_id) {
  if (!debug_edge[edge_id]) { 
    debug_edge[edge_id] = 1;
    __prefuzz_update_log();
  }
}

#endif


/* SHM setup. */

static void __afl_map_shm() {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  static u8 tmp[4];
  s32 child_pid;


  int read_pipe, write_pipe;


  // TODO: sperate sanitized binary and non-sanitized for coverage tracking
  read_pipe = FORKSRV_FD;
  write_pipe = FORKSRV_FD + 1;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */
  
  if (write(write_pipe, tmp, 4) != 4) return ;
 

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(read_pipe, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {

      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(read_pipe);
        close(write_pipe);
        return ;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(write_pipe, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(write_pipe, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {
// #ifdef PREFUZZ_DATA_INST
      memset(__afl_area_ptr, 0, SHM_SIZE);
// #else 
//       memset(__afl_area_ptr, 0, MAP_SIZE);
// #endif
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}



/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {
#ifdef PREFUZZ_DBG
    u8 stat = __init_dbg_file();
    if (stat) PFATAL("failed initalized dbg fd, check your path!");
#endif
    __afl_start_forkserver();
    __afl_map_shm();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}


