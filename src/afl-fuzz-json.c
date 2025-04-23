#include "afl-fuzz-json.h"
#include "afl-fuzz.h"


int double_is_equal(double d1, double d2) {
    return fabs(d1 - d2) < 1e-10;
}

// Read the JSON file and parse it using cJSON, then return the cJSON object.
cJSON* readin_json_file(const char* filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, "Could not open file %s\n", filename);
        return NULL;
    }

    // Find the size of the file to allocate buffer
    fseek(file, 0, SEEK_END);
    unsigned long long file_size = ftell(file);
    if (file_size == 0) {
        fprintf(stderr, "File %s is empty\n", filename);
        fclose(file);
        return NULL;
    }
    fseek(file, 0, SEEK_SET);

    // Allocate memory to store file contents
    char *content = (char*)malloc(file_size + 1);
    if (content == NULL) {
        fprintf(stderr, "Memory allocation failed\n");
        fclose(file);
        return NULL;
    }

    // Read file content into the buffer
    fread(content, 1, file_size, file);
    content[file_size] = '\0';  // Null terminate the string

    // Parse the JSON content
    cJSON *json = cJSON_Parse(content);
    free(content);  // Free the buffer after parsing

    fclose(file);

    return json;
}


// test one simple json file readin 
void test_simple_json_readin() {
    const char* filename = "../aflpp_benchmarks/zlib/zlib_uncompress_fuzzer_bb2attributes.json";
    cJSON *json = readin_json_file(filename);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", filename);
        return;
    }

    print_json_content(json);

    cJSON_Delete(json);  // Free the cJSON object
}


// test all json files readin
void test_all_jsons_readin() {

    const char* benchmarks_path = "../aflpp_benchmarks";
    
    const char* target_programs[] = {
        "bloaty",
        "curl",
        "freetype2",
        "harfbuzz",
        "lcms",
        "mbedtls",
        "openthread",
        "proj4",
        "re2",
        "zlib"
    };
    
    const char* target_names[] = {
        "fuzz_target",
        "curl_fuzzer",
        "ftfuzzer",
        "hb-shape-fuzzer",
        "cms_transform_fuzzer",
        "fuzz_dtlsclient",
        "ot-ip6-send-fuzzer",
        "proj_crs_to_crs_fuzzer",
        "fuzzer",
        "zlib_uncompress_fuzzer"
    };
    
    const char* json_suffixs[] = {
        "_bb2attributes.json",
        "_loc2addrs.json",
        "_loc2functions.json",
        "_loc2neighbors.json"
    };

    int target_programs_size = sizeof(target_programs) / sizeof(target_programs[0]);
    int json_suffixs_size = sizeof(json_suffixs) / sizeof(json_suffixs[0]);
    int failed_cnt = 0;

    for (int i = 0; i < target_programs_size; i++) {
        for (int j = 0; j < json_suffixs_size; j++) {
            
            char filename[256];
            snprintf(filename, sizeof(filename), "%s/%s/%s%s", 
                benchmarks_path, target_programs[i], target_names[i], json_suffixs[j]);
            
            cJSON *json = readin_json_file(filename);
            if (json == NULL) {
                failed_cnt += 1;
                fprintf(stderr, "Failed to read JSON file %s\n", filename);
                continue;
            }

            // print_json_content(json);

            cJSON_Delete(json);  // Free the cJSON object
        }
    }

    printf("Total failed to read JSON files: %d\n", failed_cnt);
    if (failed_cnt == 0) {
        printf("All target jsons are readable.\n");
    } else {
        printf("Some target jsons are not readable.\n");
    }
}

// print out json content on stdout
void print_json_content(cJSON* json_content) {
    if (json_content == NULL) {
        fprintf(stderr, "JSON content is NULL\n");
        return;
    }

    // Print the JSON object
    char *json_string = cJSON_Print(json_content);
    if (json_string != NULL) {
        printf("JSON content:\n%s\n", json_string);
        free(json_string);
    } else {
        fprintf(stderr, "Failed to print JSON object\n");
    }
}


// get score for cJSON array
double cjson_get_score_for_array(cJSON* cjson) {
    if (cjson == NULL || !cJSON_IsArray(cjson)) {
        fprintf(stderr, "Invalid cJSON array\n");
        return 0.0;
    }

    double res = 0.0;
    cJSON *item = NULL;

    cJSON_ArrayForEach(item, cjson) {
        if (cJSON_IsNumber(item)) {
            res += item->valuedouble * item->valuedouble;
        }
    }

    return sqrt(res);
}

double get_score_for_array(double attributes[]) {
    double res = 0.0;
    for (int i = 0; i < ATTRIBUTES_NUMBER; ++i) {
        res += attributes[i] * attributes[i];
    }

    return sqrt(res);
}


void add_bb_count_key(struct afl_state* afl, int bb_random_val) {
    struct basic_block_count *bbc = NULL;
    HASH_FIND_INT(afl->bb2count, &bb_random_val, bbc);
    
    // if bbc not found in bb2count, create a new one
    if (bbc == NULL) {
        bbc = (struct basic_block_count*)malloc(sizeof(struct basic_block_count));
        bbc->bb_random = bb_random_val;
        bbc->count = 0;
        // add bbc->bb_random as key bbc as value to bb2count hashtable
        HASH_ADD_INT(afl->bb2count, bb_random, bbc);
    }
}


void add_bb_count(struct afl_state* afl, int bb) {
    struct basic_block_count *bbc = NULL;
    HASH_FIND_INT(afl->bb2count, &bb, bbc);
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


void funafl_parse_cjson(struct afl_state* afl, cJSON* cjson, int parse_mode) {
    /*
    * parse_mode = 0: parse bb2attributes | {'str': [double, double, ...], ...}
    * parse_mode = 1: parse bb2attributes_not_first
    * parse_mode = 2: parse loc2bbs | {'str': [int, int, ...], ...}
    */

    if (cjson == NULL) {
        fprintf(stderr, "Invalid cJSON object\n");
        return;
    }

    struct basic_blocks *bb = NULL;
    struct loc2bbs *l2b = NULL;

    cJSON *item = NULL;
    cJSON *key = NULL;

    // Iterate through the JSON object
    cJSON_ArrayForEach(item, cjson) {
        if (cJSON_IsObject(item)) {
            key = cJSON_GetObjectItem(item, "key");
            if (key && cJSON_IsString(key)) {
                int loc = atoi(key->valuestring);
                
                if (parse_mode == 0) { // parse bb2attributes first
                    
                    HASH_FIND_INT(afl->bb2attributes, &loc, bb);
                    if (bb == NULL) {
                        bb = calloc(1, sizeof(struct basic_blocks));
                        bb->bb_random = loc;
                        HASH_ADD_INT(afl->bb2attributes, bb_random, bb);
                        add_bb_count_key(afl, loc);
                    }

                    cJSON* values = item->child;
                    if (cJSON_IsArray(values)) {
                        cJSON* value = NULL;
                        int idx = 0;
                        cJSON_ArrayForEach(value, values) {
                            if (idx < ATTRIBUTES_NUMBER) {
                                bb->attributes_seed[idx] = value->valuedouble;
                                bb->attributes_energy[idx] = value->valuedouble;
                                idx++;
                            } else {
                                fprintf(stderr, "Exceeded maximum number of attributes\n");
                                break;
                            }
                        }

                        bb->score_seed = get_score_for_array(bb->attributes_seed);
                        bb->score_energy = get_score_for_array(bb->attributes_energy);

                    } else {
                        fprintf(stderr, "Invalid attributes format, which should be array\n");
                        return;
                    }

                } else if (parse_mode == 1) { // parse bb2attributes not first
                    
                    HASH_FIND_INT(afl->bb2attributes, &loc, bb);
                    if (bb == NULL) {
                        fprintf(stderr, "error: bb not found while parsing bb2attributes not first\n");
                        return;
                    }

                    cJSON* values = item->child;
                    if (cJSON_IsArray(values)) {
                        cJSON* value = NULL;
                        int idx = 0;
                        cJSON_ArrayForEach(value, values) {
                            if (idx < ATTRIBUTES_NUMBER) {
                                bb->attributes_seed[idx] = value->valuedouble;
                                idx++;
                            } else {
                                fprintf(stderr, "Exceeded maximum number of attributes\n");
                                break;
                            }
                        }

                        bb->score_seed = get_score_for_array(bb->attributes_seed);

                    } else {
                        fprintf(stderr, "Invalid attributes format, which should be array\n");
                        return;
                    }

                } else if (parse_mode == 2) { // parse loc2bbs

                    HASH_FIND_INT(afl->record_loc2bbs, &loc, l2b);
                    if (l2b == NULL) {
                        l2b = calloc(1, sizeof(struct loc2bbs));
                        l2b->loc = loc;
                        l2b->length = 0;
                        HASH_ADD_INT(afl->record_loc2bbs, loc, l2b);
                    }

                    cJSON* values = item->child;
                    if (cJSON_IsArray(values)) {
                        cJSON* value = NULL;
                        cJSON_ArrayForEach(value, values) {
                            l2b->bbs[l2b->length++] = value->valueint;
                            if (l2b->length >= 20) {
                                fprintf(stderr, "Exceeded maximum number of functions\n");
                                break;
                            }
                        }
                    } else {
                        fprintf(stderr, "Invalid loc2bbs format, which should be array\n");
                        return;
                    }

                } else { // invalid parse mode
                    fprintf(stderr, "Invalid parse mode\n");
                    return;
                }

            } else {
                fprintf(stderr, "Invalid data key format, which should be string\n");
                return;
            }

        } else {
            fprintf(stderr, "Invalid JSON format\n");
            return;
        }
    }

}


void read_bb2attributes(struct afl_state* afl, u8* base_name, u8* target_name) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s%s", 
        base_name, target_name, "_bb2attributes.json");

    cJSON *json = readin_json_file(filename);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", filename);
        return;
    }

    funafl_parse_cjson(afl, json, 0);

    cJSON_Delete(json);  // Free the cJSON object
}

void read_bb2attributes_not_first(struct afl_state* afl, u8* base_name, u8* fuzz_out) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s%s",
        fuzz_out, base_name, "_bb2attributes.json");

    cJSON *json = readin_json_file(filename);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", filename);
        return;
    }

    funafl_parse_cjson(afl, json, 1);

    cJSON_Delete(json);  // Free the cJSON object
}

void read_loc2bbs(struct afl_state* afl, u8* base_name, u8* target_name) {
    char filename[256];
    snprintf(filename, sizeof(filename), "%s/%s%s", 
        base_name, target_name, "_loc2bbs.json");

    cJSON *json = readin_json_file(filename);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", filename);
        return;
    }

    funafl_parse_cjson(afl, json, 2);

    cJSON_Delete(json);  // Free the cJSON object
}


struct score_union* get_score_by_bb(struct afl_state* afl, int bb_loc) {

    struct basic_blocks* cur_bb = NULL;
    HASH_FIND_INT(afl->bb2attributes, &bb_loc, cur_bb);
    if (cur_bb == NULL) {
        fprintf(stderr, "Error: bb not found in bb2attributes\n");
        return NULL;
    }

    add_bb_count(afl, bb_loc);
    struct score_union* sc = calloc(1, sizeof(struct score_union));
    sc->seed_score = cur_bb->score_seed;
    sc->energy_score = cur_bb->score_energy;

    return sc;
}


struct score_union* get_score_with_loc_and_update_function_count(struct afl_state* afl,
    int new_tracebit_index[], int count_new_tracebit_index) {
    
    double score_seed = 0.0, score_energy = 0.0;
    struct score_union* score_record = NULL;
    int bb_num = 0, bb_num_energy = 0;

    // get score for each bb
    for (int i = 0; i < count_new_tracebit_index; ++i) {
        int loc = new_tracebit_index[i];
        struct loc2bbs* tmp_loc2bbs = NULL;
        HASH_FIND_INT(afl->record_loc2bbs, &loc, tmp_loc2bbs);
        if (tmp_loc2bbs == NULL) {
            fprintf(stderr, "Error: loc2bbs not found\n");
            continue;
        }

        for (int j = 0; j < tmp_loc2bbs->length; ++j) {
            int bb_loc = tmp_loc2bbs->bbs[j];
            score_record = get_score_by_bb(afl, bb_loc);

            if (score_record == NULL) {
                fprintf(stderr, "Error: score record not found\n");
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
    struct score_union* res = calloc(1, sizeof(struct score_union));
    // calculate average score for seed and energy
    res->seed_score = bb_num == 0?
                        afl->average_score:
                        score_seed / (double)bb_num;
    res->energy_score = bb_num_energy == 0?
                        afl->average_score_energy:
                        score_energy / (double)bb_num_energy;

    ++afl->number_score;
    ++afl->number_score_energy;
    if (afl->number_score > 2147483600 || afl->number_score_energy > 2147483600) {
        fprintf(stderr, "Error: score overflow\n");
        afl->number_score = 1;
        afl->number_score_energy = 1;
    }
    
    // update sum score
    afl->sum_score += res->seed_score;
    afl->sum_score_energy += res->energy_score;

    // calculate average score
    afl->average_score = afl->sum_score / (double)afl->number_score;
    afl->average_score_energy = afl->sum_score_energy / (double)afl->number_score_energy;

    // update max and min score
    if (res->seed_score > afl->max_score) {
        afl->max_score = res->seed_score;
    }
    if (res->seed_score < afl->min_score) {
        afl->min_score = res->seed_score;
    }

    return res;
}


/* ----- original implementation of json IO ----- */
/*
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


void add_bb_count_key(struct afl_state* afl, int bb_random_val) {
    struct basic_block_count *bbc = NULL;
    HASH_FIND_INT(afl->bb2count, &bb_random_val, bbc);
    
    // if bbc not found in bb2count, create a new one
    if (bbc == NULL) {
        bbc = (struct basic_block_count*)malloc(sizeof(struct basic_block_count));
        bbc->bb_random = bb_random_val;
        bbc->count = 0;
        // add bbc->bb_random as key bbc as value to bb2count hashtable
        HASH_ADD_INT(afl->bb2count, bb_random, bbc);
    }
}


void parse_content(struct afl_state* afl, char *content, int parse_mode) {
    // * parse_mode = 0: parse bb2attributes
    // * parse_mode = 1: parse bb2attributes_not_first
    // * parse_mode = 2: parse loc2bbs
    
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
            HASH_FIND_INT(afl->record_loc2bbs, &loc, l2b);
            if (l2b == NULL) {
                l2b = (struct loc2bbs*)malloc(sizeof(struct loc2bbs));
                l2b->loc = loc;
                l2b->length = 0;
                // [?] add l2b->loc as key l2b as value to record_loc2bbs hashtable
                HASH_ADD_INT(afl->record_loc2bbs, loc, l2b);
            }
        } else { // parsing bb2attributes
            HASH_FIND_INT(afl->bb2attributes, &loc, bb);
            if (bb == NULL) {
                if (parse_mode == 0) {
                    bb = (struct basic_blocks*)malloc(sizeof(struct basic_blocks));
                    bb->bb_random = loc;
                    HASH_ADD_INT(afl->bb2attributes, bb_random, bb);
                    add_bb_count_key(afl, loc);
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
                if (parse_mode == 2) { // parse loc2bbs
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


void read_bb2attributes(struct afl_state* afl, char *base_name) {
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

    parse_content(afl, content, 0);
    ck_free(input_name);
    ck_free(content);
}


void read_bb2attributes_not_first(struct afl_state* afl, u8 *base_name, u8 *fuzz_out) {
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

    parse_content(afl, content, 1);
    ck_free(input_name);
    ck_free(content);
}


void read_loc2bbs(struct afl_state* afl, char *bin_name) {
    u8 *input_name = alloc_printf("%s_loc2addrs.json", bin_name);
    
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

    parse_content(afl, content, 2);
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


void write_bb_count(struct afl_state* afl, u8 *base_name) {
    u8 *output_name = alloc_printf("%s/bb_count.txt", base_name);
    FILE *fp = fopen(output_name, "w");
    if (fp == NULL) {
        perror("<write_bb_count> Failed to open file: bb_count.txt");
        return;
    }

    struct basic_block_count *bbc = afl->bb2count;
    for (; bbc != NULL; bbc = (struct basic_block_count*)(bbc->hh.next)) {
        fprintf(fp, "%d: %d\n", bbc->bb_random, bbc->count);
    }

    ch_free(output_name);
    fclose(fp);
}


void add_bb_count(struct afl_state* afl, int bb) {
    struct basic_block_count *bbc = NULL;
    HASH_FIND_INT(afl->bb2count, &bb, bbc);
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


struct score_union *get_score_by_bb(struct afl_state* afl, int bb) {
    struct basic_blocks *cur_bb = NULL;
    // find bb in bbs2attributes hashtable and store result in cur_bb
    HASH_FIND_INT(afl->bb2attributes, &bb, cur_bb);
    if (cur_bb == NULL) {
        ACTF("<get_score_by_bb> bb not found in bbs2attributes: %d\n", bb);
        return NULL;
    }

    add_bb_count(afl, bb);
    struct score_union *sc = (struct score_union*)malloc(sizeof(struct score_union));
    sc->seed_score = cur_bb? cur_bb->score_seed: 0.0;
    sc->energy_score = cur_bb?  cur_bb->score_energy: 0.0;
    
    return sc;
}


struct score_union* get_score_with_loc_and_update_function_count(struct afl_state* afl, 
    int new_tracebit_index[], int count_new_tracebit_index) {
    
    double score_seed = 0.0, score_energy = 0.0;
    struct score_union *score_record = NULL;
    int bb_num = 0, bb_num_energy = 0;

    for (int i = 0; i < count_new_tracebit_index; ++i) {
        int loc = new_tracebit_index[i];
        struct loc2bbs *tmp_loc2bbs = NULL;
        HASH_FIND_INT(afl->record_loc2bbs, &loc, tmp_loc2bbs);
        if (tmp_loc2bbs == NULL) 
            continue;

        for (int j = 0; j < tmp_loc2bbs->length; ++j) {
            int bb_cal = tmp_loc2bbs->bbs[j];
            score_record = get_score_by_bb(afl, bb_cal);

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
                            afl->average_score: 
                            score_seed / (double)bb_num;
    result->energy_score = bb_num_energy == 0? 
                            afl->average_score_energy: 
                            score_energy / (double)bb_num_energy;

    // (!) maybe uninitialized before used
    ++afl->number_score;
    if (afl->number_score > 2147483600) {
        ACTF("<get_score_with_loc_and_update_function_count> number_score overflow\n");
        exit(-3);
    }
    // (!) maybe uninitialized before used
    afl->sum_score += result->seed_score;
    afl->average_score = afl->sum_score / afl->number_score;

    // (!) maybe uninitialized before used
    ++afl->number_score_energy;
    if (afl->number_score_energy > 2147483600) {
        ACTF("<get_score_with_loc_and_update_function_count> number_score_energy overflow\n");
        exit(-4);
    }
    // (!) maybe uninitialized before used
    afl->sum_score_energy += result->energy_score;
    afl->average_score_energy = afl->sum_score_energy / afl->number_score_energy;

    // update min and max score
    if (result->energy_score < afl->min_score) afl->min_score = result->energy_score;
    if (result->energy_score > afl->max_score) afl->max_score = result->energy_score; 

    return result;
}
*/
/* ----- original implementation of json IO ----- */
