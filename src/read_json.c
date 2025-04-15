#include "read_json.h"


int double_is_equal(double d1, double d2) {
    return fabs(d1 - d2) < 1e-10;
}


char *read_info_file(u8 *input_name) {
    FILE *fp = fopen(input_name, "r");
    if (fp == NULL) {
        perror("<read_info_file> Failed to open file");
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    int file_size = ftell(fp);
    
    fseek(fp, 0, SEEK_SET);
    char *content = (char*)ck_alloc(file_size * sizeof(char) + 1);
    fread(content, file_size, sizeof(char), fp);
    content[file_size] = '\0';
    fclose(fp);

    return content;
}


double get_score_for_each_array(double attributes[]) {
    double res = 0.0;
    for (int i = 0; i < ATTRIBUTES_NUMBER; ++i) {
        res += attributes[i] * attributes[i];
    }

    return sqrt(res);
}


void add_bb_count_key(int bb_random_val) {
    struct basic_block_count *bbc = NULL;
    HASH_FIND_INT(bb2count, &bb_random_val, bbc);
    
    // if bbc not found in bb2count, create a new one
    if (bbc == NULL) {
        bbc = (struct basic_block_count*)malloc(sizeof(struct basic_block_count));
        bbc->bb_random = bb_random_val;
        bbc->count = 0;
        // add bbc->bb_random as key bbc as value to bb2count hashtable
        HASH_ADD_INT(bb2count, bb_random, bbc);
    }
}


void parse_content(char *content, int parse_mode) {
    /*
    * parse_mode = 0: parse bb2attributes
    * parse_mode = 1: parse bb2attributes_not_first
    * parse_mode = 2: parse loc2bbs
    */
    int loc;
    const char delim = ']';
    char *item_str = strtok(content, delim);

    struct basic_blocks *bb = NULL;
    struct loc2bbs *l2b = NULL;
    while (item_str != NULL && item_str[0] != '}') {
        char *loc_str_start = strchr(item_str, '"');
        char *loc_str_end = strchr(loc_str_start + 1, '"');
        item_str = loc_str_end;

        // parse loc: loc_str contains loc string to be parsed to interger
        char *loc_str = (char*)malloc(sizeof(char) * (loc_str_end - loc_str_start));
        strncpy(loc_str, loc_str_start + 1, loc_str_end - loc_str_start - 1);
        loc_str[loc_str_end - loc_str_start - 1] = '\0';
        loc = atoi(loc_str);

        if (parse_mode == 2) { // parsing loc2bbs
            // find loc in record_loc2bbs hashtable and store result in l2b
            HASH_FIND_INT(record_loc2bbs, &loc, l2b);
            if (l2b == NULL) {
                l2b = (struct loc2bbs*)malloc(sizeof(struct loc2bbs));
                l2b->loc = loc;
                l2b->length = 0;
                // [?] add l2b->loc as key l2b as value to record_loc2bbs hashtable
                HASH_ADD_INT(record_loc2bbs, loc, l2b);
            }
        } else { // parsing bb2attributes
            HASH_FIND_INT(bbs2attributes, &loc, bb);
            if (bb == NULL) {
                if (parse_mode == 0) {
                    bb = (struct basic_blocks*)malloc(sizeof(struct basic_blocks));
                    bb->bb_random = loc;
                    HASH_ADD_INT(bbs2attributes, bb_random, bb);
                    add_bb_count_key(loc);
                } else if (parse_mode == 1) {
                    ACTF("[-] Read twice but bbs not found: %d\n", loc);
                    exit(-1);
                } else { // parse_mode >= 3
                    FATAL("<parse_content> Unknown parse mode: %d", parse_mode);
                    exit(-2);
                }
            }
        }
        free(loc_str);

        // parse val: val_str contains val string to be parsed to float
        int cnt = 0;
        char *val_str = NULL;
        char *val_str_start = strchr(item_str, '[');
        while (val_str_start != NULL) {
            item_str = val_str_start;
            char* val_str_end = strchr(item_str, ',');

            if (val_str_end == NULL) {
                if (parse_mode == 2) { // [?] parse bbs
                    int value = atoi(item_str + 1);
                    l2b->bbs[l2b->length++] = value;
                    if (l2b->length >= 20) {
                        ACTF("<parse_content> Too many functions in one loc\n");
                        break;
                    }
                } else { // parse attributes
                    float value = atof(item_str + 1);
                    if (parse_mode == 0) {
                        bb->attributes_seed[cnt] = value;
                        bb->attributes_energy[cnt++] = value;
                    } else if (parse_mode == 1) {
                        bb->attributes_seed[cnt++] = value;
                    }
                }

                break;
            } else {
                val_str = (char*)malloc(sizeof(char) * (val_str_end - val_str_start));
                strncpy(val_str, val_str_start + 1, val_str_end - val_str_start - 1);
                val_str[val_str_end - val_str_start - 1] = '\0';

                if (parse_mode == 2) { // [?] parse bbs
                    int value = atoi(val_str);
                    l2b->bbs[l2b->length++] = value;
                    if (l2b->length >= 20) {
                        ACTF("<parse_content> Too many functions in one loc\n");
                        break;
                    }
                } else {
                    float value = atof(val_str);
                    if (parse_mode == 0) {
                        bb->attributes_seed[cnt] = value;
                        bb->attributes_energy[cnt++] = value;
                    } else if (parse_mode == 1) {
                        bb->attributes_seed[cnt++] = value;
                    }
                }

                free(val_str);
                item_str = val_str_end + 1;
                // continue to delimit the val_str_start by '['
                val_str_start = strchr(item_str, ' ');
            }
        }

        // parse score
        if (parse_mode == 0) {
            bb->score_seed = get_score_for_each_array(bb->attributes_seed);
            bb->score_energy = get_score_for_each_array(bb->attributes_energy);
        } else if (parse_mode == 1) {
            bb->score_seed = get_score_for_each_array(bb->attributes_seed);
        } 

        // continue to delimit the string
        item_str = strtok(NULL, delim);
    }
}


void read_bb2attributes(char *base_name) {
    struct basic_blocks *bb = NULL;
    u8 *input_name = alloc_printf("%s_bb2attributes.json", base_name);

    ACTF("[+] Reading bb2attributes of the target binary...");
    char *content = read_info_file(input_name);

    // make sure the content is not NULL
    int retry_cnt = 0;
    while (retry_cnt < JSON_READ_RETRY && !content) {
        ++retry_cnt;
        content = read_info_file(input_name);
    }
    if (!content) {
        FATAL("<read_bb2attributes> Failed to read bb2attributes data from %s", input_name);
    }

    parse_content(content, 0);
    ck_free(input_name);
    ck_free(content);
}


void read_bb2attributes_not_first(u8 *base_name, u8 *fuzz_out) {
    struct basic_blocks *bb = NULL;
    char *last_slash = strchr(base_name, '/');
    char *bin_name = last_slash? (char*)(last_slash + 1): (char*)base_name;

    u8 *input_name = alloc_printf("%s/%s_bb2attributes_not_first.json", fuzz_out, bin_name);
    char *content = read_info_file(input_name);
    // make sure the content is not NULL
    int retry_cnt = 0;
    while (retry_cnt < JSON_READ_RETRY && !content) {
        ++retry_cnt;
        content = read_info_file(input_name);
    }
    if (!content) {
        FATAL("<read_bb2attributes_not_first> Failed to read bb2attributes data from %s", input_name);
    }

    parse_content(content, 1);
    ck_free(input_name);
    ck_free(content);
}


void read_loc2bbs(char *bin_name) {
    u8 *input_name = alloc_printf("%s_loc2addrs.json", bin_name);
    struct loc2bbs *loc2bbs_data = NULL; // <!> unused *loc2bbs
    
    ACTF("[+] Reading loc2bbs of the target binary...");
    char *content = read_info_file(input_name);

    // make sure the content is not NULL
    int retry_cnt = 0;
    while (retry_cnt < JSON_READ_RETRY && !content) {
        ++retry_cnt;
        content = read_info_file(input_name);
    }
    if (!content) {
        FATAL("<read_loc2bbs> Failed to read loc2bbs data from %s", input_name);
    }

    parse_content(content, 2);
    ck_free(content);
    ck_free(input_name);
}


void print_loc2bbs(struct loc2bbs *loc2bb) {
    // [*] print out the loc2bbs to file with specific prefix path
    FILE *fp = open("loc2bbs.txt", "w");
    struct loc2bbs *l2b = loc2bb;

    for (; l2b != NULL; l2b = (struct loc2bbs*)(l2b->hh.next)) {
        fprintf(fp, "loc: %d, length: %d\n", l2b->loc, l2b->length);

        for (int i = 0; i < l2b->length; ++i) {
            fprintf(fp, "bbs[%d]: %d\n", i, l2b->bbs[i]);
        }

        fprintf(fp, "\n");
    }

    fclose(fp);
}


void print_bb2attributes(struct basic_blocks *bbs) {
    // [*] print out the bb2attributes to file with specific prefix path
    FILE *fp = fopen("bb2attributes.txt", "w");
    if (fp == NULL) {
        perror("<print_bb2attributes> Failed to open file: bb2attributes.txt");
        return;
    }

    struct basic_blocks *bb = bbs;
    for (; bb != NULL; bb = (struct basic_blocks*)(bb->hh.next)) {
        fprintf(fp, "loc: %d, score_seed: %lf, score_energy: %lf\n", bb->bb_random, bb->score_seed, bb->score_energy);

        for (int i = 0; i < ATTRIBUTES_NUMBER; ++i) {
            fprintf(fp, "attributes_seed[%d]: %lf, attributes_energy[%d]: %lf\n", i, bb->attributes_seed[i], i, bb->attributes_energy[i]);
        }
    }

    fclose(fp);
}


/* same with print_bb2attributes */
void print_bb2attributes_not_first(struct basic_blocks *bbs) {
    // [*] print out the bb2attributes_not_first to a file with specific prefix path 
    FILE *fp = fopen("bb2attributes_not_first.txt", "w");
    if (fp == NULL) {
        perror("<print_bb2attributes_not_first> Failed to open file: bb2attributes_not_first.txt");
        return;
    }

    struct basic_blocks *bb = bbs;
    for (; bb != NULL; bb = (struct basic_blocks*)(bb->hh.next)) {
        fprintf(fp, "loc: %d, score_seed: %lf, score_energy: %lf\n", bb->bb_random, bb->score_seed, bb->score_energy);

        for (int i = 0; i < ATTRIBUTES_NUMBER; ++i) {
            fprintf(fp, "attributes_seed[%d]: %lf, attributes_energy[%d]: %lf\n", i, bb->attributes_seed[i], i, bb->attributes_energy[i]);
        }
    }

    fclose(fp);
}


void write_bb_count(u8 *base_name) {
    u8 *output_name = alloc_printf("%s/bb_count.txt", base_name);
    FILE *fp = fopen(output_name, "w");
    if (fp == NULL) {
        perror("<write_bb_count> Failed to open file: bb_count.txt");
        return;
    }

    struct basic_block_count *bbc = bb2count;
    for (; bbc != NULL; bbc = (struct basic_block_count*)(bbc->hh.next)) {
        fprintf(fp, "%d: %d\n", bbc->bb_random, bbc->count);
    }

    ch_free(output_name);
    fclose(fp);
}


void add_bb_count(int bb) {
    struct basic_block_count *bbc = NULL;
    HASH_FIND_INT(bb2count, &bb, bbc);
    if (bbc == NULL) {
        ACTF("<add_bb_count> bb not found in bb2count: %d\n", bb);
        exit(-5);
    }

    // add bb->count
    bbc->count++;
    if (bbc->count > 2147483600) {
        ACTF("<add_bb_count> bb count overflow\n");
        exit(-6);
    }
}


struct score_union *get_score_by_bb(int bb) {
    struct basic_blocks *cur_bb = NULL;
    // find bb in bbs2attributes hashtable and store result in cur_bb
    HASH_FIND_INT(bbs2attributes, &bb, cur_bb);
    if (cur_bb == NULL) {
        ACTF("<get_score_by_bb> bb not found in bbs2attributes: %d\n", bb);
        return NULL;
    }

    add_bb_count(bb);
    struct score_union *sc = (struct score_union*)malloc(sizeof(struct score_union));
    sc->seed_score = cur_bb? cur_bb->score_seed: 0.0;
    sc->energy_score = cur_bb?  cur_bb->score_energy: 0.0;
    
    return sc;
}


struct score_union* get_score_with_loc_and_update_function_count(int new_tracebit_index[], int count_new_tracebit_index) {
    double score_seed = 0.0, score_energy = 0.0;
    struct score_union *score_record = NULL;
    int bb_num = 0, bb_num_energy = 0;

    for (int i = 0; i < count_new_tracebit_index; ++i) {
        int loc = new_tracebit_index[i];
        struct loc2bbs *tmp_loc2bbs = NULL;
        HASH_FIND_INT(record_loc2bbs, &loc, tmp_loc2bbs);
        if (tmp_loc2bbs == NULL) 
            continue;

        for (int j = 0; j < tmp_loc2bbs->length; ++j) {
            int bb_cal = tmp_loc2bbs->bbs[j];
            score_record = get_score_by_bb(bb_cal);

            if (score_record != NULL) {
                score_seed += score_record->seed_score;
                score_energy += score_record->energy_score;

                if (!double_is_equal(score_record->seed_score, 0.0))
                    ++bb_num;
                
                if (!double_is_equal(score_record->energy_score, 0.0))
                    ++bb_num_energy;
            }

            free(score_record);
        }
    }

    // update score
    struct score_union *result = (struct score_union*)malloc(sizeof(struct score_union));
    result->seed_score = bb_num == 0? 
                            average_score: 
                            score_seed / (double)bb_num;
    result->energy_score = bb_num_energy == 0? 
                            average_score_energy: 
                            score_energy / (double)bb_num_energy;

    // (!) maybe uninitialized before used
    ++number_score;
    if (number_score > 2147483600) {
        ACTF("<get_score_with_loc_and_update_function_count> number_score overflow\n");
        exit(-3);
    }
    // (!) maybe uninitialized before used
    sum_score += result->seed_score;
    average_score = sum_score / number_score;

    // (!) maybe uninitialized before used
    ++number_score_energy;
    if (number_score_energy > 2147483600) {
        ACTF("<get_score_with_loc_and_update_function_count> number_score_energy overflow\n");
        exit(-4);
    }
    // (!) maybe uninitialized before used
    sum_score_energy += result->energy_score;
    average_score_energy = sum_score_energy / number_score_energy;

    // update min and max score
    if (result->energy_score < min_score) min_score = result->energy_score;
    if (result->energy_score > max_score) max_score = result->energy_score; 

    return result;
}
