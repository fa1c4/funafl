#ifndef READ_JSON_H
#define READ_JSON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <limits.h>
#include <math.h>

#include "../config.h"
#include "cJSON/cJSON.h"
#include "alloc-inl.h"
#include "types.h"
#include "uthash.h"
#include "list.h"


// need afl_state to declare read_loc2bbs & read_bb2attributes
struct afl_state;

// score struct
struct score_union {
    double seed_score;
    double energy_score;
};

struct basic_block_count {
    int bb_random;
    int count;
    UT_hash_handle hh;
};

struct basic_blocks {
    int bb_random;
    double attributes_seed[ATTRIBUTES_NUMBER];
    double attributes_energy[ATTRIBUTES_NUMBER];
    double score_seed;
    double score_energy;
    UT_hash_handle hh;
};

extern list_t bbs_list;

struct loc2bbs {
    int loc;
    int length;
    int bbs[20];
    UT_hash_handle hh;
};


// function declaration
int double_is_equal(double d1, double d2);

void add_bb_count_key(struct afl_state* afl, int bb_random_val);

void parse_content(struct afl_state* afl, char *content, int parse_mode);

void read_loc2bbs(struct afl_state* afl, char *bin_name);

void print_loc2bbs(struct loc2bbs *loc2bb);

void read_bb2attributes(struct afl_state* afl, char *base_name);

void read_bb2attributes_not_first(struct afl_state* afl, u8 *base_name, u8 *fuzz_out);

void print_bb2attributes(struct basic_blocks *bbs);

void print_bb2attributes_not_first(struct basic_blocks *bbs);

void write_bb_count(struct afl_state* afl, u8 *base_name);

void add_bb_count(struct afl_state* afl, int bb);

struct score_union *get_score_by_bb(struct afl_state* afl, int bb);

struct score_union* get_score_with_loc_and_update_function_count(struct afl_state* afl, int new_tracebit_index[], int count_new_tracebit_index);

#endif // READ_JSON_H
