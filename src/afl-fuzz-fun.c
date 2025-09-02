/*
    FunAFl module: afl-fuzz-fun.c
    Author: falca (azesinter@mail.ustc.edu.cn)
    Description: 
    The header file for the afl-fuzz-fun module, which contains the function definitions
    and macros used in the fuzzing process. This module is part of the FunAFL prototype
*/

#include "afl-fuzz-fun.h"
#include "afl-fuzz-json.h"
#include "cmplog.h"
#include "config.h"
#include "hash.h"
// #ifdef WORD_SIZE_64 // will lead to multi-definition errors
//   #include "coverage-64.h"
// #else
//   #include "coverage-32.h"
// #endif
#include "forkserver.h"


extern u32 skim(const u64 *virgin, const u64 *current, const u64 *current_end);
extern u64 classify_word(u64 word);
extern void classify_counts_mem(u64 *mem, u32 size);
/*
// External declarations for lookup tables defined in afl-fuzz-bitmap.c
extern u16      count_class_lookup16[65536];
extern const u8 simplify_lookup[256];
*/

extern void bitmap_set(u8 *map, u32 index); // funafl code needed which is declared in afl-fuzz-bitmap.c

extern u8 bitmap_read(u8 *map, u32 index); // funafl code needed which is declared in afl-fuzz-bitmap.c

u32 hashArray(u32* key, u32 start, u32 len, u32 seed, u32 range) {

  u32 hash_val = 1;
  for(u32 i = 0; i < len; i++) {
      hash_val = (hash_val * seed + key[start+i]) & (range - 1);
  }

  return hash_val & (range - 1);

}

/* New function to calculate difference between current and last function hits */
u32 funafl_calculate_testcase_func_diff(afl_state_t *afl, u32 *diff_map) {
    u32 diff_count = 0;
    u32 i;
    
    /* Calculate difference between current and last function hit maps */
    for (i = 0; i < FUNC_COUNT; i++) {
        if (afl->fsrv.func_hit_map[i] > afl->fsrv.last_func_hit_map[i]) {
            diff_map[i] = afl->fsrv.func_hit_map[i] - afl->fsrv.last_func_hit_map[i];
            diff_count++;
        } else {
            diff_map[i] = 0;
        }
    }
    
    return diff_count;
}

void funafl_update_last_func_hit_map(afl_state_t *afl) {
    if ((TRACE1 || TRACE2) && afl->fsrv.func_hit_map && afl->fsrv.last_func_hit_map)
      memcpy(afl->fsrv.last_func_hit_map, afl->fsrv.func_hit_map, FUNC_COUNT * sizeof(u32));
}


void funafl_get_testcase_func_locs(struct afl_state* afl, u32* testcase_hit_locs) {
    u32 diff_count = 0;
    
    for (u32 i = 0; i < FUNC_COUNT && diff_count < FUNC_COUNT - 1; i++) {
        if (afl->fsrv.func_hit_map[i] > afl->fsrv.last_func_hit_map[i]) {
            testcase_hit_locs[diff_count] = i;
            diff_count++;
        }
    }
    testcase_hit_locs[diff_count] = 0; // set 0 to terminate the array

    if (afl->debug && diff_count > 0) {
        fprintf(stderr, "[DEBUG] Found %u functions with increased hits\n", diff_count);
    }
}


/* count the function trace(set) hit times */
u32 funafl_get_function_trace_hash(afl_state_t *afl) {
    // define diff map
    u32 *testcase_diff_map = (u32*)calloc(1, FUNC_COUNT * sizeof(u32));
    if (testcase_diff_map == NULL) {
        perror("Memory allocation failed for testcase_diff_map");
        exit(17);
    }
    
    /* Calculate differences from last test case */
    u32 diff_count = funafl_calculate_testcase_func_diff(afl, testcase_diff_map);
    
    /* Hash only the differences (functions hit in this test case) using hash64 */
    u32 hash_val = hash64((u8*)testcase_diff_map, FUNC_COUNT * sizeof(u32), HASH_CONST);
    hash_val = hash_val % FUNC_COUNT;
    
    /* Update statistics based on current testcase function hits only */
    if (diff_count > 0) {
        afl->global_function_trace_sum++;
        if (afl->global_function_trace[hash_val] == 0)
            afl->global_function_trace_count++;
        
        if (afl->global_function_trace_count == 0) {
            printf("<afl-fuzz-fun> Error: global_function_trace_count is 0");
            free(testcase_diff_map);
            exit(7);
        }
        afl->average_function_trace = (double)afl->global_function_trace_sum / (double)afl->global_function_trace_count;
        afl->global_function_trace[hash_val]++;
        
        if (afl->global_function_trace[hash_val] > afl->max_function_trace)
            afl->max_function_trace = afl->global_function_trace[hash_val];
    }
    
    free(testcase_diff_map);
    
    return hash_val;

}


struct score_union* funafl_get_score_for_function_trace(struct afl_state* afl) {
    
    double score_seed = 0.0, score_energy = 0.0;
    struct score_union* score_record = NULL;
    u32 bb_num = 0, bb_num_energy = 0;

    u32 *testcase_hit_locs = (u32*)calloc(1, FUNC_COUNT * sizeof(u32));
    if (testcase_hit_locs == NULL) {
        perror("Memory allocation failed for testcase_hit_locs");
        exit(17);
    }
    
    /* Calculate differences from last test case */
    funafl_get_testcase_func_locs(afl, testcase_hit_locs);

    // get score for each function hit by current testcase and its bbs
    for (u32 i = 0; i < FUNC_COUNT; ++i) {
        if (testcase_hit_locs[i] == 0) break;
        u32 cur_loc = testcase_hit_locs[i];

        struct loc2bbs* tmp_loc2bbs = NULL;
        HASH_FIND_INT(afl->record_loc2bbs, &cur_loc, tmp_loc2bbs);
        if (tmp_loc2bbs == NULL) {
            if (afl->debug) fprintf(stderr, "[Error] loc2bbs not found for loc=%d\n", cur_loc);
            continue;
        }
        // function cur_loc's [bbs] average score as seed_score & energy_score
        for (u32 j = 0; j < tmp_loc2bbs->length; ++j) {
            u32 bb_addr = tmp_loc2bbs->bbs[j];
            score_record = get_score_by_bb(afl, bb_addr);

            if (score_record == NULL) {
                fprintf(stderr, "Error: score record not found for loc=0x%x\n", bb_addr);
                continue;
            }

            score_seed += score_record->seed_score;
            score_energy += score_record->energy_score;
            if (!double_is_equal(score_record->seed_score, 0.0)) {
                bb_num++;
            }
            if (!double_is_equal(score_record->energy_score, 0.0)) {
                bb_num_energy++;
            }
            
            free(score_record);
        }
    }

    // update score
    struct score_union* res = (struct score_union*)calloc(1, sizeof(struct score_union));
    // calculate average score for seed and energy
    res->seed_score = bb_num == 0?
                        afl->average_score:
                        score_seed / (double)bb_num;

    res->energy_score = bb_num_energy == 0?
                        afl->average_score_energy:
                        score_energy / (double)bb_num_energy;
    
    // update sum score
    afl->sum_score += res->seed_score;
    afl->sum_score_energy += res->energy_score;
    ++afl->number_score;
    ++afl->number_score_energy;

    // calculate average score
    if (afl->number_score == 0) {
        fprintf(stderr, "<afl-fuzz-json> Error: number_score is 0\n");
        exit(4);
    }
    if (afl->number_score_energy == 0) {
        fprintf(stderr, "<afl-fuzz-json> Error: number_score_energy is 0\n");
        exit(4);
    }
    afl->average_score = afl->sum_score / (double)afl->number_score;
    afl->average_score_energy = afl->sum_score_energy / (double)afl->number_score_energy;

    // update max and min score
    if (res->seed_score > afl->max_score) {
        afl->max_score = res->seed_score;
    }
    if (res->seed_score < afl->min_score) {
        afl->min_score = res->seed_score;
    }

    // free testcase_hit_locs 
    free(testcase_hit_locs);

    return res;
}


u32 unsigned_random_num(afl_state_t *afl, u32 limit) {

    if (unlikely(!afl->rand_cnt--) && (!afl->fixed_seed)) {
  
      ck_read(afl->fsrv.dev_urandom_fd, &afl->rand_seed, sizeof(afl->rand_seed), "/dev/urandom");
  
      srandom(afl->rand_seed[0]);
      afl->rand_cnt = (RESEED_RNG / 2) + (afl->rand_seed[1] % RESEED_RNG);
  
    }
  
    return random() % limit;

}


/*
    @param afl: afl_state_t pointer
    @param fuzz_out: the output directory without last '/'
*/
void funafl_print_trace(afl_state_t *afl, const u8* fuzz_out) {
    size_t fuzz_out_len = strlen(fuzz_out);
    size_t output_path_len = fuzz_out_len + strlen("/log_trace.txt") + 1; 
    u8 *output_path = (u8 *)malloc(output_path_len);
    if (output_path == NULL) {
        perror("<print_trace> Failed to allocate memory for output_path");
        exit(-2);
    }

    snprintf(output_path, output_path_len, "%s/log_trace.txt", fuzz_out);

    FILE* fp = fopen(output_path, "w");
    if (fp == NULL) {
        perror("<print_trace> Failed to open output file");
        free(output_path);
        exit(-3);
    }

    // get function number
    u32 function_num = *afl->fsrv.func_hit_map_len;
    for (u32 i = 0; i <= function_num; ++i) {
        fprintf(fp, "%d ", afl->fsrv.func_hit_map[i]);
    }
    fprintf(fp, "\n");

    // clear buffer and close fp
    free(output_path);
    fflush(fp);
    fclose(fp);
}


/* Updates the virgin bits, then reflects whether a new count or a new tuple is
 * seen in ret. */
void funafl_discover_word(u8 *ret, u64 *current, u64 *virgin) {
    /* Optimize for (*current & *virgin) == 0 - i.e., no bits in current bitmap
       that have not been already cleared from the virgin map - since this will
       almost always be the case. */
    if (*current & *virgin) {
  
        if (likely(*ret < 2)) {
  
            u8 *cur = (u8 *)current;
            u8 *vir = (u8 *)virgin;
  
            /* Looks like we have not found any new bytes yet; see if any non-zero
            bytes in current[] are pristine in virgin[]. */  
            if ((cur[0] && vir[0] == 0xff) || (cur[1] && vir[1] == 0xff) ||
                (cur[2] && vir[2] == 0xff) || (cur[3] && vir[3] == 0xff) ||
                (cur[4] && vir[4] == 0xff) || (cur[5] && vir[5] == 0xff) ||
                (cur[6] && vir[6] == 0xff) || (cur[7] && vir[7] == 0xff)) {
                    
                    *ret = 2;

            }
            else
                *ret = 1;

        }

        *virgin &= ~*current;
  
    }

}


u8 funafl_has_new_bits(afl_state_t *afl, u8* virgin_map) {

#ifdef WORD_SIZE_64

    u64 *current = (u64 *)afl->fsrv.trace_bits;
    u64 *virgin = (u64 *)virgin_map;

    u32 i = ((afl->fsrv.real_map_size + 7) >> 3);
  
#else
  
    u32 *current = (u32 *)afl->fsrv.trace_bits;
    u32 *virgin = (u32 *)virgin_map;
  
    u32 i = ((afl->fsrv.real_map_size + 3) >> 2);
  
#endif                                                     /* ^WORD_SIZE_64 */
  
    u8 ret = 0;
    while (i--) {
  
        if (unlikely(*current)) funafl_discover_word(&ret, current, virgin);
    
        current++;
        virgin++;
  
    }
  
    if (unlikely(ret) && likely(virgin_map == afl->virgin_bits))
        afl->bitmap_changed = 1;

    return ret;
  
}


u8 funafl_has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map) {

  /* Handle the hot path first: no new coverage */
  u8 *end = afl->fsrv.trace_bits + afl->fsrv.map_size;

#ifdef WORD_SIZE_64

  if (!skim((u64 *)virgin_map, (u64 *)afl->fsrv.trace_bits, (u64 *)end))
    return 0;

#else

  if (!skim((u32 *)virgin_map, (u32 *)afl->fsrv.trace_bits, (u32 *)end))
    return 0;

#endif                                                     /* ^WORD_SIZE_64 */
  classify_counts(&afl->fsrv);
  return funafl_has_new_bits(afl, virgin_map);

}


void funafl_update_bitmap_score(afl_state_t *afl, struct queue_entry* q) {

    u32 i;
    u64 fav_factor;
    u64 fuzz_p2;
  
    if (unlikely(afl->schedule >= FAST && afl->schedule < RARE)) {
  
        fuzz_p2 = 0;  // Skip the fuzz_p2 comparison
  
    } else if (unlikely(afl->schedule == RARE)) {
  
        fuzz_p2 = next_pow2(afl->n_fuzz[q->n_fuzz_entry]);
  
    } else {
  
        fuzz_p2 = q->fuzz_level;
  
    }
  
    if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {
  
        fav_factor = q->len << 2;
  
    } else {
  
        fav_factor = q->exec_us * q->len; 
  
    }

    d64 seed_score = q->seed_score;
    // comment [25-9]
    // u32 q_hit = afl->global_function_trace[q->function_trace_hash];

    /* For every byte set in afl->fsrv.trace_bits[], see if there is a previous
       winner, and how it compares to us. */
    for (i = 0; i < afl->fsrv.map_size; ++i) {
  
      if (afl->fsrv.trace_bits[i]) {
  
        if (afl->top_rated[i]) {
            // note: didn't make sense to change keep ratio yet [25-9]
            // u32 top_rated_hit = afl->global_function_trace[afl->top_rated[i]->function_trace_hash];
            // bool trace_start1 = (afl->global_function_trace_sum > (afl->global_function_trace_count * TRACE_START1));
            // bool trace_start2 = (afl->max_function_trace > (afl->average_function_trace * TRACE_START2));

            // if (TRACE1 && trace_start1 && trace_start2) {
            //     if (!double_is_equal(top_rated_hit, 0.0) && q_hit > top_rated_hit) {
            //         d64 keep_ratio = (d64)(q_hit - top_rated_hit) / (d64)(top_rated_hit);
                    
            //         if (keep_ratio > TRACE_KEEP) 
            //             continue;
            //     }
            // }

            if (double_is_equal(seed_score, 0.0) || double_is_equal(afl->top_rated[i]->seed_score, 0.0) || !SEED) {
                if (fav_factor > afl->top_rated[i]->exec_us * afl->top_rated[i]->len)
                    continue;
            } else {
                if (afl->top_rated[i]->seed_score * RATIO_SEED_SELECT > seed_score)
                    continue;
                if (fav_factor > afl->top_rated[i]->exec_us * afl->top_rated[i]->len)
                    continue;
            }

            /* Faster-executing or smaller test cases are favored. */
            u64 top_rated_fav_factor;
            u64 top_rated_fuzz_p2;
    
            if (unlikely(afl->schedule >= FAST && afl->schedule < RARE)) {
    
                top_rated_fuzz_p2 = 0;  // Skip the fuzz_p2 comparison
    
            } else if (unlikely(afl->schedule == RARE)) {
    
                top_rated_fuzz_p2 =
                    next_pow2(afl->n_fuzz[afl->top_rated[i]->n_fuzz_entry]);
    
            } else {
    
                top_rated_fuzz_p2 = afl->top_rated[i]->fuzz_level;
    
            }
    
            if (unlikely(afl->schedule >= RARE) || unlikely(afl->fixed_seed)) {
    
                top_rated_fav_factor = afl->top_rated[i]->len << 2;
    
            } else {
    
                top_rated_fav_factor =
                    afl->top_rated[i]->exec_us * afl->top_rated[i]->len;
    
            }
    
            if (likely(fuzz_p2 > top_rated_fuzz_p2)) { continue; }
    
            if (likely(fav_factor > top_rated_fav_factor)) { continue; }
    
            /* Looks like we're going to win. Decrease ref count for the
                previous winner, discard its afl->fsrv.trace_bits[] if necessary. */
    
            if (!--afl->top_rated[i]->tc_ref) {
    
                ck_free(afl->top_rated[i]->trace_mini);
                afl->top_rated[i]->trace_mini = NULL;
    
            }
  
        }
  
        /* Insert ourselves as the new winner. */
  
        afl->top_rated[i] = q;
        ++q->tc_ref;
  
        if (!q->trace_mini) {
  
          u32 len = (afl->fsrv.map_size >> 3);
          q->trace_mini = (u8 *)ck_alloc(len);
          minimize_bits(afl, q->trace_mini, afl->fsrv.trace_bits);
  
        }
  
        afl->score_changed = 1;

      }

    }

}

// setup_shm modified in afl-fuzz.c:main() 4 places

// static u8 funafl_run_target(afl_state_t *afl, char** argv, u32 timeout);
fsrv_run_result_t __attribute__((hot)) funafl_fsrv_run_target(
  afl_forkserver_t *fsrv, u32 timeout, volatile u8 *stop_soon_p) {

  s32 res;
  u32 exec_ms;
  u32 write_value = fsrv->last_run_timed_out;

#ifdef AFL_PERSISTENT_RECORD
  fsrv_run_result_t retval = FSRV_RUN_OK;
  char             *persistent_out_fmt;
#endif

#ifdef __linux__
  if (fsrv->nyx_mode) {

    static u32 last_timeout_value = 0;

    if (last_timeout_value != timeout) {

      fsrv->nyx_handlers->nyx_option_set_timeout(
          fsrv->nyx_runner, timeout / 1000, (timeout % 1000) * 1000);
      fsrv->nyx_handlers->nyx_option_apply(fsrv->nyx_runner);
      last_timeout_value = timeout;

    }

    enum NyxReturnValue ret_val =
        fsrv->nyx_handlers->nyx_exec(fsrv->nyx_runner);

    fsrv->total_execs++;

    switch (ret_val) {

      case Normal:
        return FSRV_RUN_OK;
      case Crash:
      case Asan:
        return FSRV_RUN_CRASH;
      case Timeout:
        return FSRV_RUN_TMOUT;
      case InvalidWriteToPayload:
        if (!!getenv("AFL_NYX_HANDLE_INVALID_WRITE")) { return FSRV_RUN_CRASH; }

        /* ??? */
        FATAL("FixMe: Nyx InvalidWriteToPayload handler is missing");
        break;
      case Abort:
        FATAL("Error: Nyx abort occurred...");
      case IoError:
        if (*stop_soon_p) {

          return 0;

        } else {

          FATAL("Error: QEMU-Nyx has died...");

        }

        break;
      case Error:
        FATAL("Error: Nyx runtime error has occurred...");
        break;

    }

    return FSRV_RUN_OK;

  }

#endif
  /* After this memset, fsrv->trace_bits[] are effectively volatile, so we
     must prevent any earlier operations from venturing into that
     territory. */

  /* If the binary is not instrumented, we don't care about the coverage. Make
   * it a bit faster */
  if (!fsrv->san_but_not_instrumented) {

#ifdef __linux__
    if (likely(!fsrv->nyx_mode)) {

        memset(fsrv->trace_bits, 0, fsrv->map_size);

        /* funafl code */
        memset(fsrv->func_hit_map, 0, FUNC_COUNT * sizeof(u32));
        
        // memset(fsrv->loc2curloc_map, 0, MAP_SIZE * sizeof(u32));
        /* end of funafl code */

        MEM_BARRIER();

    }

#else
    memset(fsrv->trace_bits, 0, fsrv->map_size);
    
    /* funafl code */
    memset(fsrv->func_hit_map, 0, FUNC_COUNT * sizeof(u32));

    // memset(fsrv->loc2curloc_map, 0, MAP_SIZE * sizeof(u32));
    /* end of funafl code */
    
    MEM_BARRIER();
#endif

  }

  /* we have the fork server (or faux server) up and running
  First, tell it if the previous run timed out. */

  if ((res = write(fsrv->fsrv_ctl_fd, &write_value, 4)) != 4) {

    if (*stop_soon_p) { return 0; }
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

  fsrv->last_run_timed_out = 0;

  if ((res = read(fsrv->fsrv_st_fd, &fsrv->child_pid, 4)) != 4) {

    if (*stop_soon_p) { return 0; }
    RPFATAL(res, "Unable to request new process from fork server (OOM?)");

  }

#ifdef AFL_PERSISTENT_RECORD
  // end of persistent loop?
  if (unlikely(fsrv->persistent_record &&
               fsrv->persistent_record_pid != fsrv->child_pid)) {

    fsrv->persistent_record_pid = fsrv->child_pid;
    u32 idx, val;
    if (unlikely(!fsrv->persistent_record_idx))
      idx = fsrv->persistent_record - 1;
    else
      idx = fsrv->persistent_record_idx - 1;
    val = fsrv->persistent_record_len[idx];
    memset((void *)fsrv->persistent_record_len, 0,
           fsrv->persistent_record * sizeof(u32));
    fsrv->persistent_record_len[idx] = val;

  }

#endif

  if (fsrv->child_pid <= 0) {

    if (*stop_soon_p) { return 0; }

    if ((fsrv->child_pid & FS_OPT_ERROR) &&
        FS_OPT_GET_ERROR(fsrv->child_pid) == FS_ERROR_SHM_OPEN)
      FATAL(
          "Target reported shared memory access failed (perhaps increase "
          "shared memory available).");

    FATAL("Fork server is misbehaving (OOM?)");

  }

  if (unlikely(fsrv->late_send)) {

    fsrv->late_send(fsrv->custom_data_ptr, fsrv->custom_input,
                    fsrv->custom_input_len);

  }

  exec_ms = read_s32_timed(fsrv->fsrv_st_fd, &fsrv->child_status, timeout,
                           stop_soon_p);

  if (exec_ms > timeout) {

    /* If there was no response from forkserver after timeout milliseconds,
    we kill the child. The forkserver should inform us afterwards */

    s32 tmp_pid = fsrv->child_pid;
    if (tmp_pid > 0) {

      kill(tmp_pid, fsrv->child_kill_signal);
      fsrv->child_pid = -1;

    }

    fsrv->last_run_timed_out = 1;
    if (read(fsrv->fsrv_st_fd, &fsrv->child_status, 4) < 4) { exec_ms = 0; }

  }

  if (!exec_ms) {

    if (*stop_soon_p) { return 0; }
    SAYF("\n" cLRD "[-] " cRST
         "Unable to communicate with fork server. Some possible reasons:\n\n"
         "    - You've run out of memory. Use -m to increase the the memory "
         "limit\n"
         "      to something higher than %llu.\n"
         "    - The binary or one of the libraries it uses manages to "
         "create\n"
         "      threads before the forkserver initializes.\n"
         "    - The binary, at least in some circumstances, exits in a way "
         "that\n"
         "      also kills the parent process - raise() could be the "
         "culprit.\n"
         "    - If using persistent mode with QEMU, "
         "AFL_QEMU_PERSISTENT_ADDR "
         "is\n"
         "      probably not valid (hint: add the base address in case of "
         "PIE)"
         "\n\n"
         "If all else fails you can disable the fork server via "
         "AFL_NO_FORKSRV=1.\n",
         fsrv->mem_limit);
    RPFATAL(res, "Unable to communicate with fork server");

  }

  if (!WIFSTOPPED(fsrv->child_status)) { fsrv->child_pid = -1; }

  fsrv->total_execs++;

  /* Any subsequent operations on fsrv->trace_bits must not be moved by the
     compiler below this point. Past this location, fsrv->trace_bits[]
     behave very normally and do not have to be treated as volatile. */

  MEM_BARRIER();

  /* Report outcome to caller. */

  /* Was the run unsuccessful? */
  if (unlikely(*(u32 *)fsrv->trace_bits == EXEC_FAIL_SIG)) {

    return FSRV_RUN_ERROR;

  }

  /* Did we timeout? */
  if (unlikely(fsrv->last_run_timed_out)) {

    fsrv->last_kill_signal = fsrv->child_kill_signal;

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(fsrv->persistent_record)) {

      retval = FSRV_RUN_TMOUT;
      persistent_out_fmt = "%s/hangs/RECORD:%06u,cnt:%06u%s%s";
      goto store_persistent_record;

    }

#endif

    return FSRV_RUN_TMOUT;

  }

  /* Did we crash?
  In a normal case, (abort) WIFSIGNALED(child_status) will be set.
  MSAN in uses_asan mode uses a special exit code as it doesn't support
  abort_on_error. On top, a user may specify a custom AFL_CRASH_EXITCODE.
  Handle all three cases here. */

  if (unlikely(
          /* A normal crash/abort */
          (WIFSIGNALED(fsrv->child_status)) ||
          /* special handling for msan and lsan */
          (fsrv->uses_asan &&
           (WEXITSTATUS(fsrv->child_status) == MSAN_ERROR ||
            WEXITSTATUS(fsrv->child_status) == LSAN_ERROR)) ||
          /* the custom crash_exitcode was returned by the target */
          (fsrv->uses_crash_exitcode &&
           WEXITSTATUS(fsrv->child_status) == fsrv->crash_exitcode))) {

    /* For a proper crash, set last_kill_signal to WTERMSIG, else set it to 0 */
    fsrv->last_kill_signal =
        WIFSIGNALED(fsrv->child_status) ? WTERMSIG(fsrv->child_status) : 0;

#ifdef AFL_PERSISTENT_RECORD
    if (unlikely(fsrv->persistent_record)) {

      retval = FSRV_RUN_CRASH;
      persistent_out_fmt = "%s/crashes/RECORD:%06u,cnt:%06u%s%s";
      goto store_persistent_record;

    }

#endif

    return FSRV_RUN_CRASH;

  }

  /* success :) */
  return FSRV_RUN_OK;

#ifdef AFL_PERSISTENT_RECORD
store_persistent_record: {

  char fn[PATH_MAX];
  u32  i, writecnt = 0;
  for (i = 0; i < fsrv->persistent_record; ++i) {

    u32 entry = (i + fsrv->persistent_record_idx) % fsrv->persistent_record;
    u8 *data = fsrv->persistent_record_data[entry];
    u32 len = fsrv->persistent_record_len[entry];
    if (likely(len && data)) {

      snprintf(
          fn, sizeof(fn), persistent_out_fmt, fsrv->persistent_record_dir,
          fsrv->persistent_record_cnt, writecnt++,
          ((afl_state_t *)(fsrv->afl_ptr))->file_extension ? "." : "",
          ((afl_state_t *)(fsrv->afl_ptr))->file_extension
              ? (const char *)((afl_state_t *)(fsrv->afl_ptr))->file_extension
              : "");
      int fd = open(fn, O_CREAT | O_TRUNC | O_WRONLY, 0644);
      if (fd >= 0) {

        ck_write(fd, data, len, fn);
        close(fd);

      }

    }

  }

  ++fsrv->persistent_record_cnt;

  return retval;

}

#endif

}


/* Execute target application, monitoring for timeouts. Return status
   information. The called program will update afl->fsrv->trace_bits. */

fsrv_run_result_t __attribute__((hot)) funafl_fuzz_run_target(afl_state_t      *afl,
                                                       afl_forkserver_t *fsrv,
                                                       u32 timeout) {
  // funafl code: store mutatation time
  u64 mut_start_us, mut_stop_us;

#ifdef PROFILING
  static u64      time_spent_start = 0;
  struct timespec spec;
  if (time_spent_start) {

    u64 current;
    clock_gettime(CLOCK_REALTIME, &spec);
    current = (spec.tv_sec * 1000000000) + spec.tv_nsec;
    time_spent_working += (current - time_spent_start);

  }

#endif

  fsrv_run_result_t res = funafl_fsrv_run_target(fsrv, timeout, &afl->stop_soon);

#ifdef __AFL_CODE_COVERAGE
  if (unlikely(!fsrv->persistent_trace_bits)) {

    // On the first run, we allocate the persistent map to collect coverage.
    fsrv->persistent_trace_bits = (u8 *)malloc(fsrv->map_size);
    memset(fsrv->persistent_trace_bits, 0, fsrv->map_size);

  }

  for (u32 i = 0; i < fsrv->map_size; ++i) {

    if (fsrv->persistent_trace_bits[i] != 255 && fsrv->trace_bits[i]) {

      fsrv->persistent_trace_bits[i]++;

    }

  }

#endif

  /* If post_run() function is defined in custom mutator, the function will be
     called each time after AFL++ executes the target program. */
  mut_start_us = get_cur_time_us();
  if (unlikely(afl->custom_mutators_count)) {

    LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

      if (unlikely(el->afl_custom_post_run)) {

        el->afl_custom_post_run(el->data);

      }

    });

  }
  mut_stop_us = get_cur_time_us();
  afl->mut_time += mut_stop_us - mut_start_us;

#ifdef PROFILING
  clock_gettime(CLOCK_REALTIME, &spec);
  time_spent_start = (spec.tv_sec * 1000000000) + spec.tv_nsec;
#endif

  return res;

}

// static u8 funafl_calibrate_case(afl_state_t *afl, char** argv, struct queue_entry* q, u8* use_mem, u32 handicap, u8 from_queue,int flag);

/* Calibrate a new test case. This is done when processing the input directory
   to warn about flaky or otherwise problematic test cases early on; and when
   new paths are discovered to detect variable behavior and so on. */

u8 funafl_calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem,
                  u32 handicap, u8 from_queue) {

  u8 fault = 0, new_bits = 0, var_detected = 0, hnb = 0,
     first_run = (q->exec_cksum == 0);
  u64 start_us, stop_us, diff_us;
  s32 old_sc = afl->stage_cur, old_sm = afl->stage_max;
  u32 use_tmout = afl->fsrv.exec_tmout;
  u8 *old_sn = afl->stage_name;

  u64 calibration_start_us = get_cur_time_us();
  if (unlikely(afl->shm.cmplog_mode)) { q->exec_cksum = 0; }

  /* Be a bit more generous about timeouts when resuming sessions, or when
     trying to calibrate already-added finds. This helps avoid trouble due
     to intermittent latency. */

  if (!from_queue || afl->resuming_fuzz) {

    use_tmout = MAX(afl->fsrv.exec_tmout + CAL_TMOUT_ADD,
                    afl->fsrv.exec_tmout * CAL_TMOUT_PERC / 100);

  }

  ++q->cal_failed;

  afl->stage_name = "calibration";
  afl->stage_max = afl->afl_env.afl_cal_fast ? CAL_CYCLES_FAST : CAL_CYCLES;

  /* Make sure the forkserver is up before we do anything, and let's not
     count its spin-up time toward binary calibration. */

  if (!afl->fsrv.fsrv_pid) {

    if (afl->fsrv.cmplog_binary &&
        afl->fsrv.init_child_func != cmplog_exec_child) {

      FATAL("BUG in afl-fuzz detected. Cmplog mode not set correctly.");

    }

    afl_fsrv_start(&afl->fsrv, afl->argv, &afl->stop_soon,
                   afl->afl_env.afl_debug_child);

    if (afl->fsrv.support_shmem_fuzz && !afl->fsrv.use_shmem_fuzz) {

      afl_shm_deinit(afl->shm_fuzz);
      ck_free(afl->shm_fuzz);
      afl->shm_fuzz = NULL;
      afl->fsrv.support_shmem_fuzz = 0;
      afl->fsrv.shmem_fuzz = NULL;

    }

  }

  u8 saved_afl_post_process_keep_original =
      afl->afl_env.afl_post_process_keep_original;
  afl->afl_env.afl_post_process_keep_original = 1;

  /* we need a dummy run if this is LTO + cmplog */
  if (unlikely(afl->shm.cmplog_mode)) {

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = funafl_fuzz_run_target(afl, &afl->fsrv, use_tmout);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) q->bitsmap_size = afl->bitsmap_size;
#endif

  }

  if (q->exec_cksum) {

    memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);
    hnb = funafl_has_new_bits(afl, afl->virgin_bits);
    if (hnb > new_bits) { new_bits = hnb; }

  }

  start_us = get_cur_time_us();

  for (afl->stage_cur = 0; afl->stage_cur < afl->stage_max; ++afl->stage_cur) {

    if (unlikely(afl->debug)) {

      DEBUGF("calibration stage %d/%d\n", afl->stage_cur + 1, afl->stage_max);

    }

    u64 cksum;

    (void)write_to_testcase(afl, (void **)&use_mem, q->len, 1);

    fault = funafl_fuzz_run_target(afl, &afl->fsrv, use_tmout);

    // update the time spend in calibration after each execution, as those may
    // be slow
    update_calibration_time(afl, &calibration_start_us);

    /* afl->stop_soon is set by the handler for Ctrl+C. When it's pressed,
       we want to bail out quickly. */

    if (afl->stop_soon || fault != afl->crash_mode) { goto abort_calibration; }

    if (!afl->non_instrumented_mode && !afl->stage_cur &&
        !count_bytes(afl, afl->fsrv.trace_bits)) {

      fault = FSRV_RUN_NOINST;
      goto abort_calibration;

    }

#ifdef INTROSPECTION
    if (unlikely(!q->bitsmap_size)) q->bitsmap_size = afl->bitsmap_size;
#endif

    classify_counts(&afl->fsrv);
    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
    if (q->exec_cksum != cksum) {

      hnb = funafl_has_new_bits(afl, afl->virgin_bits);
      if (hnb > new_bits) { new_bits = hnb; }

      /* funafl code */
      if (SEED || ENERGY) {
          afl->method_change++;
          struct score_union* sc = funafl_get_score_for_function_trace(afl);
          
          q->seed_score = sc->seed_score;
          q->energy_score = sc->energy_score;
          free(sc);
      }

      if (TRACE1 || TRACE2) {
          q->function_trace_hash = funafl_get_function_trace_hash(afl);
      }
      

      if (q->exec_cksum) {

        u32 i;

        for (i = 0; i < afl->fsrv.map_size; ++i) {

          if (unlikely(!afl->var_bytes[i]) &&
              unlikely(afl->first_trace[i] != afl->fsrv.trace_bits[i])) {

            afl->var_bytes[i] = 1;
            // ignore the variable edge by setting it to fully discovered
            afl->virgin_bits[i] = 0;

          }

        }

        if (unlikely(!var_detected && !afl->afl_env.afl_no_warn_instability)) {

          // note: from_queue seems to only be set during initialization
          if (afl->afl_env.afl_no_ui || from_queue) {

            WARNF("instability detected during calibration");

          } else if (afl->debug) {

            DEBUGF("instability detected during calibration\n");

          }

        }

        var_detected = 1;
        afl->stage_max =
            afl->afl_env.afl_cal_fast ? CAL_CYCLES : CAL_CYCLES_LONG;

      } else {

        q->exec_cksum = cksum;
        memcpy(afl->first_trace, afl->fsrv.trace_bits, afl->fsrv.map_size);

      }

    }

  }

  if (unlikely(afl->fixed_seed)) {

    diff_us = (u64)(afl->fsrv.exec_tmout - 1) * (u64)afl->stage_max;

  } else {

    stop_us = get_cur_time_us();
    diff_us = stop_us - start_us;
    diff_us -= afl->mut_time; // funafl code: leave over mutatation time
    q->mut_time = afl->mut_time;
    afl->mut_time = 0; // reset after cutting off mutation time 
    if (unlikely(!diff_us)) { ++diff_us; }

  }

  afl->total_cal_us += diff_us;
  afl->total_cal_cycles += afl->stage_max;

  /* OK, let's collect some stats about the performance of this test case.
     This is used for fuzzing air time calculations in calculate_score(). */

  if (unlikely(!afl->stage_max)) {

    // Pretty sure this cannot happen, yet scan-build complains.
    FATAL("BUG: stage_max should not be 0 here! Please report this condition.");

  }

  if (double_is_equal(afl->stage_max, 0.0)) {
    fprintf(stderr, "<afl-fuzz-fun> Error: afl->stage_max is 0.0!");
    exit(-12);
  }
  q->exec_us = diff_us / afl->stage_max;
  if (unlikely(!q->exec_us)) { q->exec_us = 1; }

  q->bitmap_size = count_bytes(afl, afl->fsrv.trace_bits);
  q->handicap = handicap;
  q->cal_failed = 0;

  afl->total_bitmap_size += q->bitmap_size;
  ++afl->total_bitmap_entries;

  funafl_update_bitmap_score(afl, q);

  /* If this case didn't result in new output from the instrumentation, tell
     parent. This is a non-critical problem, but something to warn the user
     about. */

  if (!afl->non_instrumented_mode && first_run && !fault && !new_bits) {

    fault = FSRV_RUN_NOBITS;

  }

abort_calibration:

  afl->afl_env.afl_post_process_keep_original =
      saved_afl_post_process_keep_original;

  if (new_bits == 2 && !q->has_new_cov) {

    q->has_new_cov = 1;
    ++afl->queued_with_cov;

  }

  /* Mark variable paths. */

  if (var_detected) {

    afl->var_byte_count = count_bytes(afl, afl->var_bytes);

    if (!q->var_behavior) {

      mark_as_variable(afl, q);
      ++afl->queued_variable;

    }

  }

  afl->stage_name = old_sn;
  afl->stage_cur = old_sc;
  afl->stage_max = old_sm;

  if (!first_run) { show_stats(afl); }

  update_calibration_time(afl, &calibration_start_us);
  return fault;

}


u8 __attribute__((hot)) funafl_save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault) {

  if (unlikely(len == 0)) { return 0; }

  if (unlikely(fault == FSRV_RUN_TMOUT && afl->afl_env.afl_ignore_timeouts)) {

    if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

      classify_counts(&afl->fsrv);
      u64 cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

      // Saturated increment
      if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
        afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

    }

    return 0;

  }

  u8  fn[PATH_MAX];
  u8 *queue_fn = "";
  u8  new_bits = 0, keeping = 0, res, classified = 0, is_timeout = 0,
     need_hash = 1;
  s32 fd;
  u64 cksum = 0;
  u32 cksum_simplified = 0, cksum_unique = 0;
  u8  san_fault = 0;
  u8  san_idx = 0;
  u8  feed_san = 0;

  afl->san_case_status = 0;

  /* Update path frequency. */

  /* Generating a hash on every input is super expensive. Bad idea and should
     only be used for special schedules */
  if (unlikely(afl->schedule >= FAST && afl->schedule <= RARE)) {

    classify_counts(&afl->fsrv);
    classified = 1;
    need_hash = 0;

    cksum = hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);

    /* Saturated increment */
    if (likely(afl->n_fuzz[cksum % N_FUZZ_SIZE] < 0xFFFFFFFF))
      afl->n_fuzz[cksum % N_FUZZ_SIZE]++;

  }

  /* Only "normal" inputs seem interested to us */
  if (likely(fault == afl->crash_mode)) {

    if (unlikely(afl->san_binary_length) &&
        likely(afl->san_abstraction == SIMPLIFY_TRACE)) {

      memcpy(afl->san_fsrvs[0].trace_bits, afl->fsrv.trace_bits,
             afl->fsrv.map_size);
      classify_counts_mem((u64 *)afl->san_fsrvs[0].trace_bits,
                          afl->fsrv.map_size);
      simplify_trace(afl, afl->san_fsrvs[0].trace_bits);

      // Note: Original SAND implementation used XXHASH32
      cksum_simplified =
          hash32(afl->san_fsrvs[0].trace_bits, afl->fsrv.map_size, HASH_CONST);

      if (unlikely(!bitmap_read(afl->simplified_n_fuzz, cksum_simplified))) {

        feed_san = 1;
        bitmap_set(afl->simplified_n_fuzz, cksum_simplified);

      }

    }

    if (unlikely(afl->san_binary_length) &&
        unlikely(afl->san_abstraction == COVERAGE_INCREASE)) {

      /* Check if the input increase the coverage */
      new_bits = funafl_has_new_bits_unclassified(afl, afl->virgin_bits);

      if (unlikely(new_bits)) { feed_san = 1; }

    }

    if (unlikely(afl->san_binary_length) &&
        likely(afl->san_abstraction == UNIQUE_TRACE)) {

      cksum_unique =
          hash32(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      if (unlikely(!bitmap_read(afl->n_fuzz_dup, cksum) &&
                   fault == afl->crash_mode)) {

        feed_san = 1;
        bitmap_set(afl->n_fuzz_dup, cksum_unique);

      }

    }

    if (feed_san) {

      /* The input seems interested to other sanitizers, feed it into extra
       * binaries. */

      for (san_idx = 0; san_idx < afl->san_binary_length; san_idx++) {

        len = write_to_testcase(afl, &mem, len, 0);
        san_fault = funafl_fuzz_run_target(afl, &afl->san_fsrvs[san_idx],
                                    afl->san_fsrvs[san_idx].exec_tmout);

        // DEBUGF("ASAN Result: %hhd\n", asan_fault);

        if (unlikely(san_fault && fault == afl->crash_mode)) {

          /* sanitizers discovers distinct bugs! */
          afl->san_case_status |= SAN_CRASH_ONLY;

        }

        if (san_fault == FSRV_RUN_CRASH) {

          /* Treat this execution as fault detected by ASAN */
          // fault = san_fault;

          /* That's pretty enough, break to avoid more overhead. */
          break;

        } else {

          // or keep san_fault as ok
          san_fault = FSRV_RUN_OK;

        }

      }

    }

  }

  /* If there is no crash, everything is fine. */
  if (likely(fault == afl->crash_mode)) {

    /* Keep only if there are new bits in the map, add to queue for
       future fuzzing, etc. */
    if (!unlikely(afl->san_abstraction == COVERAGE_INCREASE && feed_san)) {

      /* If we are in coverage increasing abstraction and have fed input to
         sanitizers, we are sure it has new bits.*/
      new_bits = funafl_has_new_bits_unclassified(afl, afl->virgin_bits);

    }

    if (likely(!new_bits)) {

      if (san_fault == FSRV_RUN_OK) {

        if (unlikely(afl->crash_mode)) { ++afl->total_crashes; }
        return 0;

      } else {

        afl->san_case_status |= NON_COV_INCREASE_BUG;
        fault = san_fault;
        classified = new_bits;
        goto may_save_fault;

      }

    }

    fault = san_fault;
    classified = new_bits;

  save_to_queue:

#ifndef SIMPLE_FILES

    if (!afl->afl_env.afl_sha1_filenames) {

      queue_fn = alloc_printf(
          "%s/queue/id:%06u,%s%s%s", afl->out_dir, afl->queued_items,
          describe_op(afl, new_bits + is_timeout,
                      NAME_MAX - strlen("id:000000,")),
          afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");

    } else {

      const char *hex = sha1_hex(mem, len);
      queue_fn = alloc_printf(
          "%s/queue/%s%s%s", afl->out_dir, hex, afl->file_extension ? "." : "",
          afl->file_extension ? (const char *)afl->file_extension : "");
      ck_free((char *)hex);

    }

#else

    queue_fn = alloc_printf(
        "%s/queue/id_%06u", afl->out_dir, afl->queued_items,
        afl->file_extension ? "." : "",
        afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */
    fd = permissive_create(afl, queue_fn);
    if (likely(fd >= 0)) {

      ck_write(fd, mem, len, queue_fn);
      close(fd);

    }

    add_to_queue(afl, queue_fn, len, 0);

    /* funafl code */
    if (SEED || ENERGY) {

        afl->method_change++;
        struct score_union* sc = funafl_get_score_for_function_trace(afl);
        
        afl->queue_top->seed_score = sc->seed_score;
        afl->queue_top->energy_score = sc->energy_score;

        free(sc);

    }

    if (TRACE1 || TRACE2) {

        afl->queue_top->function_trace_hash = funafl_get_function_trace_hash(afl);

    }
    /* end of funafl code */

    if (unlikely(afl->fuzz_mode) &&
        likely(afl->switch_fuzz_mode && !afl->non_instrumented_mode)) {

      if (afl->afl_env.afl_no_ui) {

        ACTF("New coverage found, switching back to exploration mode.");

      }

      afl->fuzz_mode = 0;

    }

#ifdef INTROSPECTION
    if (afl->custom_mutators_count && afl->current_custom_fuzz) {

      LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

        if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

          const char *ptr = el->afl_custom_introspection(el->data);

          if (ptr != NULL && *ptr != 0) {

            fprintf(afl->introspection_file, "QUEUE CUSTOM %s = %s\n", ptr,
                    afl->queue_top->fname);

          }

        }

      });

    } else if (afl->mutation[0] != 0) {

      fprintf(afl->introspection_file, "QUEUE %s = %s\n", afl->mutation,
              afl->queue_top->fname);

    }

#endif

    if (new_bits == 2) {

      afl->queue_top->has_new_cov = 1;
      ++afl->queued_with_cov;

    }

    if (unlikely(need_hash && new_bits)) {

      /* due to classify counts we have to recalculate the checksum */
      afl->queue_top->exec_cksum =
          hash64(afl->fsrv.trace_bits, afl->fsrv.map_size, HASH_CONST);
      need_hash = 0;

    }

    /* For AFLFast schedules we update the new queue entry */
    if (likely(cksum)) {

      afl->queue_top->n_fuzz_entry = cksum % N_FUZZ_SIZE;
      afl->n_fuzz[afl->queue_top->n_fuzz_entry] = 1;

    }

    /* Try to calibrate inline; this also calls update_bitmap_score() when
       successful. */

    /* funafl code */
    // res = calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);
    res = funafl_calibrate_case(afl, afl->queue_top, mem, afl->queue_cycle - 1, 0);
    /* end of funafl code */

    if (unlikely(res == FSRV_RUN_ERROR)) {

      FATAL("Unable to execute target application");

    }

    if (likely(afl->q_testcase_max_cache_size)) {

      queue_testcase_store_mem(afl, afl->queue_top, mem);

    }

    keeping = 1;

  }

may_save_fault:
  switch (fault) {

    case FSRV_RUN_TMOUT:

      /* Timeouts are not very interesting, but we're still obliged to keep
         a handful of samples. We use the presence of new bits in the
         hang-specific bitmap as a signal of uniqueness. In "non-instrumented"
         mode, we just keep everything. */

      ++afl->total_tmouts;

      if (afl->saved_hangs >= KEEP_UNIQUE_HANG) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!funafl_has_new_bits(afl, afl->virgin_tmout)) { return keeping; }

      }

      is_timeout = 0x80;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file,
                      "UNIQUE_TIMEOUT CUSTOM %s = %s\n", ptr,
                      afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_TIMEOUT %s\n", afl->mutation);

      }

#endif

      /* Before saving, we make sure that it's a genuine hang by re-running
         the target with a more generous timeout (unless the default timeout
         is already generous). */

      if (afl->fsrv.exec_tmout < afl->hang_tmout) {

        u8  new_fault;
        u32 tmp_len = write_to_testcase(afl, &mem, len, 0);

        if (likely(tmp_len)) {

          len = tmp_len;

        } else {

          len = write_to_testcase(afl, &mem, len, 1);

        }

        new_fault = funafl_fuzz_run_target(afl, &afl->fsrv, afl->hang_tmout);
        classify_counts(&afl->fsrv);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!afl->stop_soon && new_fault == FSRV_RUN_CRASH) {

          goto keep_as_crash;

        }

        if (afl->stop_soon || new_fault != FSRV_RUN_TMOUT) {

          if (afl->afl_env.afl_keep_timeouts) {

            ++afl->saved_tmouts;
            goto save_to_queue;

          } else {

            return keeping;

          }

        }

      }

#ifndef SIMPLE_FILES

      if (!afl->afl_env.afl_sha1_filenames) {

        snprintf(fn, PATH_MAX, "%s/hangs/id:%06llu,%s%s%s", afl->out_dir,
                 afl->saved_hangs,
                 describe_op(afl, 0, NAME_MAX - strlen("id:000000,")),
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");

      } else {

        const char *hex = sha1_hex(mem, len);
        snprintf(fn, PATH_MAX, "%s/hangs/%s%s%s", afl->out_dir, hex,
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
        ck_free((char *)hex);

      }

#else

      snprintf(fn, PATH_MAX, "%s/hangs/id_%06llu%s%s", afl->out_dir,
               afl->saved_hangs, afl->file_extension ? "." : "",
               afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_hangs;

      afl->last_hang_time = get_cur_time();

      break;

    case FSRV_RUN_CRASH:

    keep_as_crash:

      /* This is handled in a manner roughly similar to timeouts,
         except for slightly different limits and no need to re-run test
         cases. */

      ++afl->total_crashes;

      if (afl->saved_crashes >= KEEP_UNIQUE_CRASH) { return keeping; }

      if (likely(!afl->non_instrumented_mode)) {

        if (unlikely(!classified)) {

          classify_counts(&afl->fsrv);
          classified = 1;

        }

        simplify_trace(afl, afl->fsrv.trace_bits);

        if (!funafl_has_new_bits(afl, afl->virgin_crash)) { return keeping; }

      }

      if (unlikely(!afl->saved_crashes) &&
          (afl->afl_env.afl_no_crash_readme != 1)) {

        write_crash_readme(afl);

      }

#ifndef SIMPLE_FILES

      if (!afl->afl_env.afl_sha1_filenames) {

        snprintf(fn, PATH_MAX, "%s/crashes/id:%06llu,sig:%02u,%s%s%s",
                 afl->out_dir, afl->saved_crashes, afl->fsrv.last_kill_signal,
                 describe_op(afl, 0, NAME_MAX - strlen("id:000000,sig:00,")),
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");

      } else {

        const char *hex = sha1_hex(mem, len);
        snprintf(fn, PATH_MAX, "%s/crashes/%s%s%s", afl->out_dir, hex,
                 afl->file_extension ? "." : "",
                 afl->file_extension ? (const char *)afl->file_extension : "");
        ck_free((char *)hex);

      }

#else

      snprintf(fn, PATH_MAX, "%s/crashes/id_%06llu_%02u%s%s", afl->out_dir,
               afl->saved_crashes, afl->fsrv.last_kill_signal,
               afl->file_extension ? "." : "",
               afl->file_extension ? (const char *)afl->file_extension : "");

#endif                                                    /* ^!SIMPLE_FILES */

      ++afl->saved_crashes;
#ifdef INTROSPECTION
      if (afl->custom_mutators_count && afl->current_custom_fuzz) {

        LIST_FOREACH(&afl->custom_mutator_list, struct custom_mutator, {

          if (afl->current_custom_fuzz == el && el->afl_custom_introspection) {

            const char *ptr = el->afl_custom_introspection(el->data);

            if (ptr != NULL && *ptr != 0) {

              fprintf(afl->introspection_file, "UNIQUE_CRASH CUSTOM %s = %s\n",
                      ptr, afl->queue_top->fname);

            }

          }

        });

      } else if (afl->mutation[0] != 0) {

        fprintf(afl->introspection_file, "UNIQUE_CRASH %s\n", afl->mutation);

      }

#endif
      if (unlikely(afl->infoexec)) {

        // if the user wants to be informed on new crashes - do that
#if !TARGET_OS_IPHONE
        // we dont care if system errors, but we dont want a
        // compiler warning either
        // See
        // https://stackoverflow.com/questions/11888594/ignoring-return-values-in-c
        (void)(system(afl->infoexec) + 1);
#else
        WARNF("command execution unsupported");
#endif

      }

      afl->last_crash_time = get_cur_time();
      afl->last_crash_execs = afl->fsrv.total_execs;

      break;

    case FSRV_RUN_ERROR:
      FATAL("Unable to execute target application");

    default:
      return keeping;

  }

  /* If we're here, we apparently want to save the crash or hang
     test case, too. */

  fd = permissive_create(afl, fn);
  if (fd >= 0) {

    ck_write(fd, mem, len, fn);
    close(fd);

  }

#ifdef __linux__
  if (afl->fsrv.nyx_mode && fault == FSRV_RUN_CRASH) {

    u8 fn_log[PATH_MAX];

    (void)(snprintf(fn_log, PATH_MAX, "%s.log", fn) + 1);
    fd = open(fn_log, O_WRONLY | O_CREAT | O_EXCL, DEFAULT_PERMISSION);
    if (unlikely(fd < 0)) { PFATAL("Unable to create '%s'", fn_log); }

    u32 nyx_aux_string_len = afl->fsrv.nyx_handlers->nyx_get_aux_string(
        afl->fsrv.nyx_runner, afl->fsrv.nyx_aux_string,
        afl->fsrv.nyx_aux_string_len);

    ck_write(fd, afl->fsrv.nyx_aux_string, nyx_aux_string_len, fn_log);
    close(fd);

  }

#endif

  return keeping;

}


// static u32 funafl_calculate_score(afl_state_t *afl, struct queue_entry* q);
u32 funafl_calculate_score(afl_state_t *afl, struct queue_entry *q) {

  u32 cal_cycles = afl->total_cal_cycles;
  u32 bitmap_entries = afl->total_bitmap_entries;

  if (unlikely(!cal_cycles)) { cal_cycles = 1; }
  if (unlikely(!bitmap_entries)) { bitmap_entries = 1; }

  u32 avg_exec_us = afl->total_cal_us / cal_cycles;
  u32 avg_bitmap_size = afl->total_bitmap_size / bitmap_entries;
  u32 perf_score = 100;

  /* Adjust score based on execution speed of this path, compared to the
     global average. Multiplier ranges from 0.1x to 3x. Fast inputs are
     less expensive to fuzz, so we're giving them more air time. */

  // TODO BUG FIXME: is this really a good idea?
  // This sounds like looking for lost keys under a street light just because
  // the light is better there.
  // Longer execution time means longer work on the input, the deeper in
  // coverage, the better the fuzzing, right? -mh

  if (likely(afl->schedule < RARE) && likely(!afl->fixed_seed)) {

    if (q->exec_us * 0.1 > avg_exec_us) {

      perf_score = 10;

    } else if (q->exec_us * 0.25 > avg_exec_us) {

      perf_score = 25;

    } else if (q->exec_us * 0.5 > avg_exec_us) {

      perf_score = 50;

    } else if (q->exec_us * 0.75 > avg_exec_us) {

      perf_score = 75;

    } else if (q->exec_us * 4 < avg_exec_us) {

      perf_score = 300;

    } else if (q->exec_us * 3 < avg_exec_us) {

      perf_score = 200;

    } else if (q->exec_us * 2 < avg_exec_us) {

      perf_score = 150;

    }

  }

  /* Adjust score based on bitmap size. The working theory is that better
     coverage translates to better targets. Multiplier from 0.25x to 3x. */

  if (q->bitmap_size * 0.3 > avg_bitmap_size) {

    perf_score *= 3;

  } else if (q->bitmap_size * 0.5 > avg_bitmap_size) {

    perf_score *= 2;

  } else if (q->bitmap_size * 0.75 > avg_bitmap_size) {

    perf_score *= 1.5;

  } else if (q->bitmap_size * 3 < avg_bitmap_size) {

    perf_score *= 0.25;

  } else if (q->bitmap_size * 2 < avg_bitmap_size) {

    perf_score *= 0.5;

  } else if (q->bitmap_size * 1.5 < avg_bitmap_size) {

    perf_score *= 0.75;

  }

  /* Adjust score based on handicap. Handicap is proportional to how late
     in the game we learned about this path. Latecomers are allowed to run
     for a bit longer until they catch up with the rest. */

  if (q->handicap >= 4) {

    perf_score *= 4;
    q->handicap -= 4;

  } else if (q->handicap) {

    perf_score *= 2;
    --q->handicap;

  }

  /* Final adjustment based on input depth, under the assumption that fuzzing
     deeper test cases is more likely to reveal stuff that can't be
     discovered with traditional fuzzers. */

  switch (q->depth) {

    case 0 ... 3:
      break;
    case 4 ... 7:
      perf_score *= 2;
      break;
    case 8 ... 13:
      perf_score *= 3;
      break;
    case 14 ... 25:
      perf_score *= 4;
      break;
    default:
      perf_score *= 5;

  }

  u32         n_items;
  double      factor = 1.0;
  long double fuzz_mu;

  switch (afl->schedule) {

    case EXPLORE:
      break;

    case SEEK:
      break;

    case EXPLOIT:
      factor = MAX_FACTOR;
      break;

    case COE:
      fuzz_mu = 0.0;
      n_items = 0;

      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      u32 i;
      for (i = 0; i < afl->queued_items; i++) {

        if (likely(!afl->queue_buf[i]->disabled)) {

          fuzz_mu += log2(afl->n_fuzz[afl->queue_buf[i]->n_fuzz_entry]);
          n_items++;

        }

      }

      if (unlikely(!n_items)) { FATAL("Queue state corrupt"); }

      fuzz_mu = fuzz_mu / n_items;

      if (log2(afl->n_fuzz[q->n_fuzz_entry]) > fuzz_mu) {

        /* Never skip favourites */
        if (!q->favored) factor = 0;

        break;

      }

    // Fall through
    case FAST:

      // Don't modify unfuzzed seeds
      if (!q->fuzz_level) break;

      switch ((u32)log2(afl->n_fuzz[q->n_fuzz_entry])) {

        case 0 ... 1:
          factor = 4;
          break;

        case 2 ... 3:
          factor = 3;
          break;

        case 4:
          factor = 2;
          break;

        case 5:
          break;

        case 6:
          if (!q->favored) factor = 0.8;
          break;

        case 7:
          if (!q->favored) factor = 0.6;
          break;

        default:
          if (!q->favored) factor = 0.4;
          break;

      }

      if (q->favored) factor *= 1.15;

      break;

    case LIN:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor = q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case QUAD:
      // Don't modify perf_score for unfuzzed seeds
      if (!q->fuzz_level) break;

      factor =
          q->fuzz_level * q->fuzz_level / (afl->n_fuzz[q->n_fuzz_entry] + 1);
      break;

    case MMOPT:
      /* -- this was a more complex setup, which is good, but competed with
         -- rare. the simpler algo however is good when rare is not.
        // the newer the entry, the higher the pref_score
        perf_score *= (1 + (double)((double)q->depth /
        (double)afl->queued_items));
        // with special focus on the last 8 entries
        if (afl->max_depth - q->depth < 8) perf_score *= (1 + ((8 -
        (afl->max_depth - q->depth)) / 5));
      */
      // put focus on the last 5 entries
      if (afl->max_depth - q->depth < 5) { perf_score *= 2; }

      break;

    case RARE:

      // increase the score for every bitmap byte for which this entry
      // is the top contender
      perf_score += (q->tc_ref * 10);
      // the more often fuzz result paths are equal to this queue entry,
      // reduce its value
      perf_score *= (1 - (double)((double)afl->n_fuzz[q->n_fuzz_entry] /
                                  (double)afl->fsrv.total_execs));

      break;

    default:
      PFATAL("Unknown Power Schedule");

  }

  if (unlikely(afl->schedule >= EXPLOIT && afl->schedule <= QUAD)) {

    if (factor > MAX_FACTOR) { factor = MAX_FACTOR; }
    perf_score *= factor / POWER_BETA;

  }

  // MOpt mode
  if (afl->limit_time_sig != 0 && afl->max_depth - q->depth < 3) {

    perf_score *= 2;

  } else if (afl->schedule != COE && perf_score < 1) {

    // Add a lower bound to AFLFast's energy assignment strategies
    perf_score = 1;

  }

  /* funafl code */
  if (afl->dynamic_enabled) { 
    // only enable the dynamic update when coverage increase rate is low
    d64 times_hit = (d64)afl->global_function_trace[q->function_trace_hash];
    if (double_is_equal(times_hit, 0.0)) {
      times_hit = 1.0;
    }

    d64 cur_score = afl->queue_cur->energy_score;
    
    if (TRACE2) {
    
      if (times_hit < afl->average_function_trace) {

          perf_score *= pow(2, afl->average_function_trace / times_hit);
    
      } else {
    
          perf_score *= pow(2, afl->average_function_trace / times_hit) - 1;
    
      }
    
    }

    if (ENERGY && afl->energy_times > ENERGY_START_TIME) {
      
      if (double_is_equal(afl->max_score, 0.0) && double_is_equal(afl->min_score, FLT_MAX)) {
          ACTF("NO SCORE");
          exit(-2);
      }
      
      if (double_is_equal(cur_score, 0.0)) {
          ACTF("NO CUR SCORE");
          exit(-3);
      }
      
      // normalizing the score
      if (double_is_equal(afl->average_score_energy, 0.0)) {
          afl->average_score_energy = 1.0;
      } 
      perf_score *= cur_score / afl->average_score_energy;

    }

    if (afl->energy_times <= ENERGY_START_TIME) 
      afl->energy_times++;
  }
  /* end of funafl code */

  /* Make sure that we don't go over limit. */

  if (perf_score > afl->havoc_max_mult * 100) {

    perf_score = afl->havoc_max_mult * 100;

  }

  return perf_score;

}
