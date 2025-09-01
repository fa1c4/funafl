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

#include "config.h"
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
    uint32_t bb_loc;
    uint32_t count;
    UT_hash_handle hh;
};

struct basic_blocks {
    uint32_t bb_loc;
    double attributes_seed[ATTRIBUTES_NUMBER];
    double attributes_energy[ATTRIBUTES_NUMBER];
    double score_seed;
    double score_energy;
    UT_hash_handle hh;
};

extern list_t bbs_list;

struct loc2bbs {
    uint32_t loc;
    uint32_t length;
    uint32_t bbs[BB_MAX_COUNT];
    UT_hash_handle hh;
};


// function declaration
cJSON* readin_json_file(const u8* filename);

char *read_info_file(u8 *input_name);

int double_is_equal(double d1, double d2);

void add_bb_count_key(struct afl_state* afl, uint32_t bb_loc_val);

void parse_content(struct afl_state* afl, char *content, int parse_mode);

void read_loc2bbs(struct afl_state* afl, u8* target_path);

void print_json_content(cJSON* json_content);

void print_loc2bbs(struct loc2bbs *loc2bb);

void read_bb2attributes(struct afl_state* afl, u8* target_path);

void read_bb2attributes_dynamic(struct afl_state* afl, u8* target_path);

void print_bb2attributes(struct basic_blocks *bbs);

void print_bb2attributes_not_first(struct basic_blocks *bbs);

void write_bb_count(struct afl_state* afl, u8 *base_name);

void add_bb_count(struct afl_state* afl, uint32_t bb_addr);

struct score_union* get_score_by_bb(struct afl_state* afl, uint32_t bb_addr);

// void init_dynamic_func_hit_update(u8* target_path);
void init_dynamic_func_hit_update();

// void update_function2count(struct afl_state* afl, u8* target_path);
void update_function2count(struct afl_state* afl);

#endif // READ_JSON_H
