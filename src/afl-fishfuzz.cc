#include "afl-fuzz.h"

#include <jsoncpp/json/json.h>
#include <fstream>
#include <algorithm>
#include <sys/time.h>
#include <map>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>



#ifdef __cplusplus
extern "C" {
#endif 

std::map<u32, std::map<u32, u32>> func_dist_map;

static u64 get_cur_time_cxx(void) {

  struct timeval tv;
  struct timezone tz;

  gettimeofday(&tv, &tz);

  return (tv.tv_sec * 1000ULL) + (tv.tv_usec / 1000);

}

/* initialize loading static maps */

void initialized_dist_map(afl_state_t *afl, struct fishfuzz_info *ff_info) {

  Json::Value shortest_dist_map;
  Json::Reader reader;
  std::string temporary_dir = std::getenv("TMP_DIR"), errs;
  std::ifstream dist_map(temporary_dir + "/calldst.json", std::ifstream::binary);
  
  if (!reader.parse(dist_map, shortest_dist_map, false))
    PFATAL("Failed loading dist map !");

  for (auto dst_s : shortest_dist_map.getMemberNames()) {

    std::map<u32, u32> func_shortest;
    Json::Value func_shortest_value = shortest_dist_map[dst_s];
    
    for (auto src_s : func_shortest_value.getMemberNames()) {
  
      func_shortest.insert(std::make_pair(std::stoi(src_s), func_shortest_value[src_s].asInt()));
  
    }
    
    func_dist_map.insert(std::make_pair(std::stoi(dst_s), func_shortest));
  
  }

  if (!afl->func_map_size) PFATAL("Make sure initialize before we use!");

  ff_info->unvisited_func_map = (u8*)ck_alloc(sizeof(u8) * afl->func_map_size);
  ff_info->iterated_func_map = (u8*)ck_alloc(sizeof(u8) * afl->func_map_size);

  for (int i = 0; i < FUNC_SIZE; i ++) ff_info->unvisited_func_map[i] = 1;
  
}

/* wrapper to update top_rated_explore */
void update_bitmap_score_explore(afl_state_t *afl, struct fishfuzz_info *ff_info) {

  if (!afl->virgin_funcs) return ;

  if (!ff_info->shortest_dist) {
    
    ff_info->shortest_dist = (u32 *)ck_alloc(sizeof(u32) * afl->func_map_size);

    for (u32 i = 0; i < afl->func_map_size; i ++) ff_info->shortest_dist[i] = UNREACHABLE_DIST;
  
  }

  // we only explore each seeds once, so if there are no new seeds, we don't update
  if (afl->last_explored_item == afl->queued_items && afl->last_explored_item) return ;

  for (u32 sid = afl->last_explored_item; sid < afl->queued_items; sid ++) {

    struct queue_entry *q = afl->queue_buf[sid];
    u8 has_new_func = 0;

    if (q->fuzz_level || !q->trace_func) continue;

    for (u32 i = 0; i < afl->func_map_size; i ++) {

      if (unlikely(q->trace_func[i]) && unlikely(!ff_info->iterated_func_map[i])) { has_new_func = 1; break; }
        
    }

    if (!has_new_func) continue;

    u64 fav_factor = q->len * q->exec_us;

    for (u32 dst_func = 0; dst_func < afl->func_map_size; dst_func ++) {

      if (!ff_info->unvisited_func_map[dst_func] || afl->virgin_funcs[dst_func]) continue;

      // now we don't remove explored functions 
      // if (afl->top_rated_explore[dst_func]) {

      //   if (afl->top_rated_explore[dst_func]->fuzz_level) afl->top_rated_explore[dst_func] = NULL;
      
      // }
      u32 fexp_score = 0, shortest_dist = UNREACHABLE_DIST, src_func = 0;

      for (auto iter = func_dist_map[dst_func].begin(); iter != func_dist_map[dst_func].end(); iter ++) {
      
        if (q->trace_func[iter->first]) {

          if (iter->second < shortest_dist) { src_func = iter->first; shortest_dist = iter->second; }
        
        }
      
      }

      if (shortest_dist != UNREACHABLE_DIST) fexp_score = shortest_dist * 100;

      if (fexp_score) {

        if (!afl->top_rated_explore[dst_func]) {
        
          afl->top_rated_explore[dst_func] = q; ff_info->shortest_dist[dst_func] = fexp_score;
          ff_info->last_func_time = get_cur_time_cxx(); ff_info->skip_inter_func = 0;
        
        }
        else {
        
          if (fexp_score < afl->shortest_dist[dst_func]) {
            
            afl->top_rated_explore[dst_func] = q; ff_info->shortest_dist[dst_func] = fexp_score;
            ff_info->last_func_time = get_cur_time_cxx(); ff_info->skip_inter_func = 0;

          }

          if (fexp_score == afl->shortest_dist[dst_func]) {

            if (!afl->top_rated_explore[dst_func]->fuzz_level) {
              if (fav_factor < afl->top_rated_explore[dst_func]->exec_us * afl->top_rated_explore[dst_func]->len) {
              
                afl->top_rated_explore[dst_func] = q; ff_info->shortest_dist[dst_func] = fexp_score;
                ff_info->last_func_time = get_cur_time_cxx(); ff_info->skip_inter_func = 0;

              }
            }
          }

        }
      
      }
    
    }

    for (u32 i = 0; i < afl->func_map_size; i ++) {

      if (unlikely(q->trace_func[i])) ff_info->iterated_func_map[i] = 1;
      
    } 

  }

  if (afl->last_explored_item) {
    for (u32 i = 0; i < afl->last_explored_item; i ++) {

      if (afl->queue_buf[i]->trace_func) {
        
        // avoid consuming too much memory
        ck_free(afl->queue_buf[i]->trace_func);
        afl->queue_buf[i]->trace_func = NULL;

      }

    }
  }

  afl->last_explored_item = afl->queued_items;

}


void target_ranking(afl_state_t *afl, struct fishfuzz_info *ff_info) {

  std::vector<std::uint32_t> reached_bugs;
  std::uint32_t max_value = 1;

  if (!ff_info->reach_bits_count || !ff_info->trigger_bits_count) return ;

  for (u32 i = 0; i < afl->targ_map_size; i ++) {
    
    if (ff_info->reach_bits_count[i] && !ff_info->trigger_bits_count[i]) {
      
      reached_bugs.push_back(ff_info->reach_bits_count[i]);
      
      if (max_value < ff_info->reach_bits_count[i]) max_value = ff_info->reach_bits_count[i];
    
    }
  
  }

  std::sort(reached_bugs.begin(), reached_bugs.end());
  if (max_value != 1) {

    float rate = afl->pending_not_fuzzed / afl->queued_items;
    
    if (rate < 0.2) rate = 0.1;
    
    else if (rate < 0.5) rate = 0.075;
    
    else rate = 0.05;
    
    ff_info->exploit_threshould = reached_bugs[reached_bugs.size() * rate];
  
  }

}


#ifdef __cplusplus
}
#endif 
