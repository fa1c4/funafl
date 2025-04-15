/*
    FunAFl module: afl-fuzz-fun.c
    Author: falca (azesinter@mail.ustc.edu.cn)
    Description: 
    The header file for the afl-fuzz-fun module, which contains the function definitions
    and macros used in the fuzzing process. This module is part of the FunAFL prototype
*/

#include "afl-fuzz-fun.h"


static u32 funafl_get_function_trace(afl_state_t *afl) {
    // 368-385
    if (afl->fsrv.function_index[0] > 65535) {
        ACTF("Integer overflow, please check the function index");
        exit(-1);
    }
}

/*
    @param afl: afl_state_t pointer
    @param fuzz_out: the output directory without last '/'
*/
static void funafl_print_trace(afl_state_t *afl, const u8* fuzz_out) {
    size_t fuzz_out_len = strlen(fuzz_out);
    size_t output_path_len = fuzz_out_len + strlen("/log_trace.txt") + 1; 
    u8 *output_path = (u8 *)malloc(output_path_len);
    if (output_path == NULL) {
        perror("<print_trace> Failed to allocate memory for output_path");
        exit(-2);
    }

    snprintf(output_path, output_path_len, "%s/log_trace.txt", fuzz_out);

    FILE* fp = fopen(output_path, 'w');
    if (fp == NULL) {
        perror("<print_trace> Failed to open output file");
        free(output_path);
        exit(-3);
    }

    // get function number
    u32 function_num = afl->fsrv.function_index[0];
    for (u32 i = 1; i <= function_num; ++i) {
        fprintf(fp, "%d ", afl->fsrv.function_index[i]);
    }
    fprintf(fp, "\n");

    // clear buffer and close fp
    free(output_path);
    fflush(fp);
    fclose(fp);
}


static void funafl_get_trace_bits_set_bits(afl_state_t *afl) {
    memset(new_tracebit_index, 0, 65536 * sizeof(int));
    count_new_tracebit_index = 0;
    for (u32 i = 0; i < MAP_SIZE; ++i) {
        if (afl->fsrv.trace_bits[i]) {
            new_tracebit_index[count_new_tracebit_index++] = i;
        }
    }
}

static inline u8 funafl_has_new_bits(afl_state_t *afl, u8* virgin_map) {

}


static void funafl_update_bitmap_score(afl_state_t *afl, struct queue_entry* q) {

}

// setup_shm 1505-1536

static u8 funafl_run_target(afl_state_t *afl, char** argv, u32 timeout) {

}

static u8 funafl_calibrate_case(afl_state_t *afl, char** argv, struct queue_entry* q, u8* use_mem, u32 handicap, u8 from_queue,int flag) {

}
// caller 2904

static void funafl_pivot_inputs(afl_state_t *afl) {

}

static u8 funafl_save_if_interesting(afl_state_t *afl, char** argv, void* mem, u32 len, u8 fault) {

}

static u32 funafl_calculate_score(afl_state_t *afl, struct queue_entry* q) {

}

