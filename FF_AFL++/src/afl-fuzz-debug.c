#include "afl-fuzz.h"



/* log file for fishfuzz */

void write_fishfuzz_log(afl_state_t *afl, u8 prev_mode, u8 current_mode) {
  
  if (!afl->fish_debug_log) {

    afl->fish_debug_log = alloc_printf("%s/fish_debug.log", afl->out_dir);
    afl->fish_debug_fd = fopen(afl->fish_debug_log, "w");

  }

  afl->last_log_time = get_cur_time();

  if (!afl->virgin_funcs) return ;
  u32 func_cov = 0;
  for (u32 i = 0; i < FUNC_SIZE; i ++) {
  
    if (afl->virgin_funcs[i]) func_cov += 1;

  }

  u8 *prev_mode_s, *current_mode_s;
  switch (prev_mode) {
    
    case INTRA_FUNC_EXPLORE: 
      prev_mode_s = (u8*) "ORIGINAL";
      break;
    case INTER_FUNC_EXPLORE:
      prev_mode_s = (u8*) "EXPLORE";
      break;
    default:
      prev_mode_s = (u8*) "EXPLOIT";

  }

  switch (current_mode) {
    
    case INTRA_FUNC_EXPLORE: 
      current_mode_s = (u8*) "ORIGINAL";
      break;
    case INTER_FUNC_EXPLORE:
      current_mode_s = (u8*) "EXPLORE";
      break;
    default:
      current_mode_s = (u8*) "EXPLOIT";

  }

  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->fish_debug_fd, "[%02lld:%02lld:%02lld] %s->%s : round %lld, fav %d/%d/%d, %d/%d/%d of %d are fuzzed, cov : %d/%d, violation : %d/%d.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60, 
          prev_mode_s, current_mode_s, afl->queue_cycle, afl->pending_favored, afl->queued_retryed, afl->queued_favored,
          afl->queued_fuzzed_favored, afl->queued_fuzzed_non_favored, afl->queued_fuzzed_retryed, afl->queued_items, func_cov, count_non_255_bytes(afl, afl->virgin_bits),
          afl->current_targets_reached, afl->current_targets_triggered);

}

/*
void write_exploit_log(afl_state_t *afl, u32 exploit_threshould) {
  
  if (!afl->exploit_debug_log) {

    afl->exploit_debug_log = alloc_printf("%s/exploit_debug.log", afl->out_dir);
    afl->exploit_debug_fd = fopen(afl->exploit_debug_log, "w");

  }

  u64 current_ms = get_cur_time() - afl->start_time;

  for (u32 i = 0; i < VMAP_COUNT; i ++) {
    
    if (afl->top_rated_exploit[i] && afl->reach_bits_count[i] < exploit_threshould) {

      fprintf(afl->exploit_debug_fd, "[%02lld:%02lld:%02lld] update seed %s as favored for %d\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60,
          afl->top_rated_exploit[i]->fname, i);

    }

  }


}
*/

void write_cull_log(afl_state_t *afl) {
  
  if (!afl->cull_debug_log) {

    afl->cull_debug_log = alloc_printf("%s/cull_debug.log", afl->out_dir);
    afl->cull_debug_fd = fopen(afl->cull_debug_log, "w");

  }

  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->cull_debug_fd, "[%02lld:%02lld:%02lld] origin takes %lld, explore takes %lld, exploit takes %lld, others %lld, update explore %lld.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60, 
          afl->log_cull_origin_time, afl->log_cull_explore_time, afl->log_cull_exploit_time, 
          afl->log_cull_other_time, afl->log_update_explore_time);
  

}

void write_seed_selection_log(afl_state_t *afl, u8 skip_fuzz) {

  if (!afl->seed_selec_log) {

    afl->seed_selec_log = alloc_printf("%s/seed_selec.log", afl->out_dir);
    afl->seed_selec_fd = fopen(afl->seed_selec_log, "w");

  }

  u64 current_ms = get_cur_time() - afl->start_time;

  fprintf(afl->seed_selec_fd, "[%02lld:%02lld:%02lld] %s fuzz %s seed %d, now in %s mode.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60,
          (skip_fuzz == 0) ? (u8*)"finish" : (u8*)"skip",
          afl->queue_cur->favored ? (u8*)"favored" : (u8*)"non-favored",
          afl->current_entry, (afl->fish_seed_selection == INTER_FUNC_EXPLORE) ? (u8*) "explore" :
          (afl->fish_seed_selection == INTRA_FUNC_EXPLORE ? (u8*) "origin" : (u8*) "exploit"));

}

void write_exploit_log(afl_state_t *afl) {

  if (!afl->exploit_log) {

    afl->exploit_log = alloc_printf("%s/exploit.log", afl->out_dir);
    afl->exploit_fd = fopen(afl->exploit_log, "w");

  }
  if (!afl->reach_bits_count) return ;

  u64 total_reach_cnt = 0, total_trigger_cnt = 0;
  for (u32 i = 0; i < VMAP_COUNT; i ++) {
    if (afl->reach_bits_count[i]) total_reach_cnt += afl->reach_bits_count[i];
    if (afl->trigger_bits_count[i]) total_trigger_cnt += afl->trigger_bits_count[i];
  }

  u64 current_ms = get_cur_time() - afl->start_time;
  u64 avg_reach = (afl->current_targets_reached) ? total_reach_cnt / afl->current_targets_reached : 0,
      avg_trigger = (afl->current_targets_triggered) ? total_trigger_cnt / afl->current_targets_triggered : 0;

  fprintf(afl->exploit_fd, "[%02lld:%02lld:%02lld] bug threshould %d, retry threshould %lld/%lld/%lld.\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60,
          afl->exploit_threshould, avg_trigger, avg_reach, afl->fsrv.total_execs / afl->current_targets_reached);

}


void write_develop_log(afl_state_t *afl) {

  if (!afl->dev_log) {

    afl->dev_log = alloc_printf("%s/dev.log", afl->out_dir);
    afl->dev_fd = fopen(afl->dev_log, "w");

  }
  u64 current_ms = get_cur_time() - afl->start_time;
  fprintf(afl->dev_fd, "[%02lld:%02lld:%02lld] now we have %d func and %d bbs covered, %d sanitizer targets reached and %d triggered .\n",
          current_ms / 1000 / 3600, (current_ms / 1000 / 60) % 60, (current_ms / 1000) % 60,
          afl->current_func_covered, count_non_255_bytes(afl, afl->virgin_bits),
          afl->current_targets_reached, afl->current_targets_triggered);
}

