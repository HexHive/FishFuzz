
#ifndef _CFG_WRAPPER_H
#define _CFG_WRAPPER_H

#include "types.h"
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif



struct queue_entry {

  u8* fname;                          /* File name for the test case      */
  u32 len;                            /* Input length                     */

  u8  cal_failed,                     /* Calibration failed?              */
      trim_done,                      /* Trimmed?                         */
      was_fuzzed,                     /* Had any fuzzing done yet?        */
      retry,                          /* maybe we could retry             */
      passed_det,                     /* Deterministic stages passed?     */
      // has_new_func,                   /* Has new function coverage?       */
      has_new_cov,                    /* Triggers new coverage?           */
      has_new_path,                   /* Has new path?                    */
      has_new_conf,                   /* Has new conformance?             */
      var_behavior,                   /* Variable behavior?               */
      favored,                        /* Currently favored?               */
      fs_redundant;                   /* Marked as redundant in the fs?   */

  u32 bitmap_size,                    /* Number of bits set in bitmap     */
      exec_cksum;                     /* Checksum of the execution trace  */

  u64 exec_us,                        /* Execution time (us)              */
      handicap,                       /* Number of queue cycles behind    */
      depth;                          /* Path depth                       */

  u32 bug_score,                      /* Bug score along the path         */
      exp_score,                      /* Prob to explore unvisited bugs   */
      untouched_brach,                /* unvisited cmps                   */
      conformance;                    /* Data flow feature                */
  
  double power_rate_explore,
         power_rate_exploit,
         power_rate_afl;

  u8 *trace_mini,                     /* Trace bytes, if kept             */
     *trace_cmp,                      /* Trace cmps, if kept              */
     *trace_func;                     /* Trace func, if kept              */
  u32 tc_ref;                         /* Trace bytes ref count            */

  struct queue_entry *next,           /* Next element, if any             */
                     *next_100;       /* 100 elements ahead               */

};



struct cov_queue_entry {
  struct queue_entry *queue;          /* Seed it point at                 */
  struct cov_queue_entry *next;       /* Next seed in coverage queue      */
  u32 conformance;                    /* organize seed by conformance     */
};

struct cov_queue_head {
  u8 *trace_mini;                     /* seed's exec trace in queue       */
  u8 *trace_func;                     /* Trace function.                  */
  u32 bug_score,                      /* seed's bug score in queue        */
      exp_score,                      /* seed's explore score in queue    */
      pending_not_fuzzed,             /* seed not fuzzed in cqueue        */
      pending_fuzzed_cnt,             /* times cqueue has been selected   */
      queued_paths;                   /* all seeds in the cqueue          */
  struct cov_queue_head *next;        /* next coverage queue              */
  struct cov_queue_entry *first;      /* first seed in queue              */
};

/* cmp types value */

enum {
  /* 00 */ CMP_TYPE_NONE,
  /* 01 */ CMP_TYPE_BUG,
  /* 02 */ CMP_TYPE_VAR,
  /* 03 */ CMP_TYPE_ALL
};

/* for target ranking */

struct cmp_entry {
  u8  reg_l_encoding,                 /* is left register direct_copy?    */ 
      reg_r_encoding,                 /* is right register direct_copy?   */
      conformance,                    /* min conformance                  */
      var_size,                       /* constraint's size (u8/u32/u64)?  */
      cmp_type;                       /* is this cmp a bug/var?           */
  u32 enc_pos;                        /* location that has encoding       */
  u32 func_id,                        /* coresponding func id             */
      shm_id,                         /* coresponding cmp bb id           */
      redge_id,                       /* right branch edge id             */
      ledge_id,                       /* left branch edge id              */
      lvisit_cnt,
      rvisit_cnt;
  u64 diff_bits;                      /* which bits are not covered yet   */
  u32 distance;                       /* bug's distance                   */
  u32 last_new_conf;                  /* last time we have new conf       */
  u32 bug_score;                      /* todo, for target ranking later   */
};

// extern struct cmp_entry 
//               cmp_map[VMAP_COUNT];    /* for target ranking               */

extern u8   low_freq_bits[MAP_SIZE];


extern u32 pending_vulns,             /* vulnerable not triggerd */           
           pending_canbe_reached;

extern u32  partial_virgin_bits[MAP_SIZE]; /* used for target ranking     */
extern u64  start_time;                /* Unix start time (ms)             */

// extern u8   virgin_bits[MAP_SIZE];    


// extern u32  g_max_bscore,             /* used for anual power scheduling  */
//             g_min_bscore;

extern u32  bug_freq_threshould,       /* bug score's threshould           */
            bit_freq_threshould,       /* threshould for rare visited bits */
            current_max_bscore,        /* Current max bug score found      */
            current_violation_visit,   /* current visited labels           */
            current_violation_trigger; /* current triggered labels         */

extern u32  pending_not_fuzzed,        /* Queued but not done yet          */
            pending_favored,           /* Pending favored paths            */
            queued_paths;              /* Total number of queued testcases */
extern u64  last_explore_time,         /* Time for most recent reach (ms)  */
            last_exploit_time,         /* Time for most recent trigger (ms)*/
            total_trigger_execs;       /* Total Executions to trigger      */


extern u8   score_changed;             /* Scoring for favorites changed?   */
extern u8   low_freq_bits[MAP_SIZE];


/* for cg/cfg */

void initialized_callgraph();
// void initialized_edge_map();
void initialized_func_map();
void initialized_dist_map();
void initialized_bug_map();

void update_bug_scoring(u32*, u32*);
void update_exp_scoring(struct queue_entry**, struct queue_entry*);
void update_unvisited_bfunc(u8 *);
void update_bitmap_freq(u32*);

void debug_top_func(struct queue_entry**, u8*);

void add_to_vector(u32);
u32  get_pos_length(u32);


#ifdef __cplusplus
};
#endif


#endif