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
#include "read_json.h"


/* FunAFL global avariables */
extern struct loc2bbs* record_loc2bbs;
extern struct basic_block_count* bb2count;
extern struct basic_blocks* bb2attributes;

extern int trace_bits_index_when_new_path_is_added = 0;
extern int count_new_tracebit_index = 0;
extern int new_tracebit_index[65536] = {0};

extern double average_score = 0.0;
extern double sum_score = 0.0;
extern int number_score = 0;

extern double average_score_energy = 0.0;
extern double sum_score_energy = 0.0;
extern int number_score_energy = 0;
extern d64 max_score = 0;
extern d64 min_score = FLT_MAX;

extern u32 global_function_trace[65536];
extern u32 global_function_trace_count;
extern u32 global_function_trace_sum;
extern d64 average_function_trace;
extern d64 max_function_trace;
extern int energy_times = 0;

extern int method_change = 0;
extern int not_found_new_hit = 0;
extern int not_found_base = 1;
extern int read_success = 0;


static u32 funafl_get_function_trace(afl_state_t *afl);

static void funafl_print_trace(afl_state_t *afl, const u8* fuzz_out);

static void funafl_get_trace_bits_set_bits(afl_state_t *afl);

static inline u8 funafl_funafl_has_new_bits(afl_state_t *afl, u8* virgin_map); // 962-1073

static void funafl_update_bitmap_score(afl_state_t *afl, struct queue_entry* q); // 1364-1441 comp to afl++

// setup_shm 1505-1536

static u8 funafl_run_target(afl_state_t *afl, char** argv, u32 timeout); // 2425-2629 comp to afl++

static u8 funafl_calibrate_case(afl_state_t *afl, char** argv, struct queue_entry* q, u8* use_mem,
    u32 handicap, u8 from_queue,int flag); // 2699-2856 compto afl++
// caller 2904

static void funafl_pivot_inputs(afl_state_t *afl); // 3116-3204

static u8 funafl_save_if_interesting(afl_state_t *afl, char** argv, void* mem, u32 len, u8 fault); // 3302-3494

static u32 funafl_calculate_score(afl_state_t *afl, struct queue_entry* q); // 4877-4965

// caller 5248

// fuzz_one large! 5158-6869 cmpto afl++ first

// global variable 7953

// main function 7955-near_end cmpto afl++ first








#endif // _AFL_FUZZ_FUN_H
