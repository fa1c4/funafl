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

extern struct basic_block_count *bb2count;
extern struct basic_blocks *bbs2attributes;
extern struct loc2bbs *record_loc2bbs;

extern double average_score;
extern double sum_score;
extern int number_score;
extern double average_score_energy;
extern double sum_score_energy;
extern int number_score_energy;
// modify back the d64 self-define type to double 
extern double max_score;
extern double min_score;
extern int read_success;


// function declaration
int double_is_equal(double d1, double d2);
void read_loc2bbs(char *bin_name);
void print_loc2bbs(struct loc2bbs *loc2bb);
void read_bb2attributes(char *base_name);
void read_bb2attributes_not_first(u8 *base_name, u8 *fuzz_out);
void print_bb2attributes(struct basic_blocks *bbs);
void print_bb2attributes_not_first(struct basic_blocks *bbs);
void write_bb_count(u8 *base_name);

struct score_union* get_score_with_loc_and_update_function_count(int new_tracebit_index[], int count_new_tracebit_index);

#endif // READ_JSON_H
