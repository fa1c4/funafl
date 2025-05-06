/*
    FunAFl module: afl-fuzz-fun.h 
    Author: falca (azesinter@mail.ustc.edu.cn)
    Description: 
    The header file for the afl-fuzz-fun module, which contains the function declarations
    and macros used in the fuzzing process. This module is part of the FunAFL prototype
*/

#ifndef _AFL_FUZZ_FUN_H
#define _AFL_FUZZ_FUN_H

#include "afl-fuzz.h"

#include <limits.h>
#include <float.h>
#include <math.h>

#include "types.h"


u32 funafl_get_function_trace_hash(afl_state_t *afl);

u32 unsigned_random_num(afl_state_t* afl, u32 limit);

void funafl_print_trace(afl_state_t *afl, const u8* fuzz_out);

void funafl_get_trace_bits_set_bits(afl_state_t *afl);

void funafl_discover_word(afl_state_t *afl, u8 *ret, u64 *current, u64 *virgin);

u8 funafl_has_new_bits(afl_state_t *afl, u8* virgin_map);

u8 funafl_has_new_bits_unclassified(afl_state_t *afl, u8 *virgin_map);

void funafl_update_bitmap_score(afl_state_t *afl, struct queue_entry* q);

// setup_shm 1505-1536

// 2425-2629 comp to afl++ | 2440-2443 function_index
// u8 funafl_run_target(afl_state_t *afl, char** argv, u32 timeout); 
fsrv_run_result_t __attribute__((hot)) funafl_fsrv_run_target(afl_forkserver_t *fsrv, u32 timeout, volatile u8 *stop_soon_p);

fsrv_run_result_t __attribute__((hot)) funafl_fuzz_run_target(afl_state_t *afl, afl_forkserver_t *fsrv, u32 timeout);

// u8 funafl_calibrate_case(afl_state_t *afl, struct queue_entry *q, u8 *use_mem, u32 handicap, u8 from_queue);
// 2699-2856 compto afl++ | 2764-2776
u8 funafl_calibrate_case(afl_state_t *afl, struct queue_entry* q, u8* use_mem, 
    u32 handicap, u8 from_queue, u8 cali_flag);

// calibrate_case caller 2904 -> afl-fuzz-init.c:perform_dry_run

// u8 funafl_save_if_interesting(afl_state_t *afl, char** argv, void* mem, u32 len, u8 fault); // 3302-3494
u8 __attribute__((hot)) funafl_save_if_interesting(afl_state_t *afl, void *mem, u32 len, u8 fault);

u32 funafl_calculate_score(afl_state_t *afl, struct queue_entry* q); // 4877-4965

// caller 5248

// fuzz_one->fuzz_one_original modified locally

// global variable last_modify_t & modify_t modify to main(){}

// main function: init funafl global variables
// main function: afl-fuzz-json
// main function: 

#endif // _AFL_FUZZ_FUN_H
