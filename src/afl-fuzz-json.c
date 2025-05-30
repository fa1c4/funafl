#include <unistd.h>
#include "afl-fuzz-json.h"
#include "afl-fuzz.h"


int double_is_equal(double d1, double d2) {
    return fabs(d1 - d2) < 1e-10;
}

// Read the JSON file and parse it using cJSON, then return the cJSON object.
cJSON* readin_json_file(const u8* filename) {
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
    cJSON *json_content = readin_json_file(filename);
    if (json_content == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", filename);
        return;
    }

    print_json_content(json_content);

    cJSON_Delete(json_content);  // Free the cJSON object
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

    if (sizeof(target_programs) / sizeof(*target_programs) == sizeof(target_names) / sizeof(*target_names)) {
        fprintf(stderr, "<afl-fuzz-json> Error: target_programs and target_names must have same length");
        exit(-9);
    }

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
        fprintf(stdout, "All target jsons are readable.\n");
    } else {
        fprintf(stderr, "Some target jsons are not readable.\n");
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
    
    // check res > 0.0
    if (res <= 0.0) {
        fprintf(stderr, "<afl-fuzz-json> Error: Invalid score: %f\n", res);
        exit(-10);
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

    // Iterate through the JSON object
    cJSON *item = NULL;
    cJSON_ArrayForEach(item, cjson) {
        if (!cJSON_IsArray(item)) {
            fprintf(stderr, "Invalid value format, should be array\n");
            return;
        }

        const char* key_str = item->string;
        if (key_str) {

            int loc = atoi(key_str);
            
            if (parse_mode == 0) { // parse bb2attributes first
                
                HASH_FIND_INT(afl->bb2attributes, &loc, bb);
                if (bb == NULL) {
                    bb = (struct basic_blocks*)calloc(1, sizeof(struct basic_blocks));
                    bb->bb_random = loc;
                    HASH_ADD_INT(afl->bb2attributes, bb_random, bb);
                    add_bb_count_key(afl, loc);
                }
                
                if (bb == NULL) {
                    fprintf(stderr, "<funafl_parse_cjson> Error: bb not found while parsing attributes\n");
                    return;
                }

                cJSON* value = NULL;
                int idx = 0;
                cJSON_ArrayForEach(value, item) {
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

            } else if (parse_mode == 1) { // parse bb2attributes not first
                
                HASH_FIND_INT(afl->bb2attributes, &loc, bb);
                if (bb == NULL) {
                    fprintf(stderr, "error: bb not found while parsing bb2attributes not first\n");
                    return;
                }

                cJSON* value = NULL;
                int idx = 0;
                cJSON_ArrayForEach(value, item) {
                    if (idx < ATTRIBUTES_NUMBER) {
                        bb->attributes_seed[idx] = value->valuedouble;
                        idx++;
                    } else {
                        fprintf(stderr, "Exceeded maximum number of attributes\n");
                        break;
                    }
                }

                bb->score_seed = get_score_for_array(bb->attributes_seed);

            } else if (parse_mode == 2) { // parse loc2bbs

                HASH_FIND_INT(afl->record_loc2bbs, &loc, l2b);
                if (l2b == NULL) {
                    l2b = (struct loc2bbs*)calloc(1, sizeof(struct loc2bbs));
                    l2b->loc = loc;
                    l2b->length = 0;
                    HASH_ADD_INT(afl->record_loc2bbs, loc, l2b);
                }

                cJSON* value = NULL;
                cJSON_ArrayForEach(value, item) {
                    l2b->bbs[l2b->length++] = value->valueint;
                    if (l2b->length >= 256) {
                        fprintf(stderr, "Exceeded maximum number of functions\n");
                        break;
                    }
                }

            } else { // invalid parse mode
                fprintf(stderr, "Invalid parse mode\n");
                return;
            }

        } else {
            fprintf(stderr, "Invalid data key format, which should be string\n");
            return;
        }

    }

    // debug information to makesure the count of loc2bbs correct
    if (afl->debug && parse_mode == 2) {
        printf("[INFO] Total loc2bbs count: %u\n", HASH_COUNT(afl->record_loc2bbs));
        fflush(stdout);
        sleep(5);
    }

}


void split_path(const char *path, char *dir, char *filename) {
    char *local_path = strdup(path); 

    // if the last char is '/' then set it as '\0'
    if (path[strlen(path) - 1] == '/') {
        local_path[strlen(path) - 1] = '\0';
    }

    // search for last slash
    const char *last_slash = strrchr(local_path, '/');

    if (last_slash != NULL) {
        // copy dir path
        size_t dir_len = last_slash - local_path;
        strncpy(dir, local_path, dir_len);
        dir[dir_len] = '\0';  // add '\0' at the end

        // copy filename 
        strcpy(filename, last_slash + 1);
    } else {
        // if there is no slash, assume the entire path is the filename 
        dir[0] = '\0';
        strcpy(filename, local_path);
    }
}


void read_bb2attributes(struct afl_state* afl, u8* target_path) {
    char file_path[256], dir_path[256], base_name[256];

    // split the target path
    split_path(target_path, dir_path, base_name);

    snprintf(file_path, sizeof(file_path), "%s/aicfg/%s%s", 
        dir_path, base_name, "_bb2attributes.json");

    cJSON *json = readin_json_file(file_path);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", file_path);
        fprintf(stderr, "target_path: %s\n", target_path);
        fprintf(stderr, "dir_path: %s\n", dir_path);
        fprintf(stderr, "base_name: %s\n", base_name);
        exit(-16);
    }

    funafl_parse_cjson(afl, json, 0);

    cJSON_Delete(json);  // Free the cJSON object
}

void read_bb2attributes_not_first(struct afl_state* afl, u8* base_name, u8* fuzz_out) {
    char file_path[256];

    snprintf(file_path, sizeof(file_path), "%s/aicfg/%s%s",
        fuzz_out, base_name, "_bb2attributes.json");

    cJSON *json = readin_json_file(file_path);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", file_path);
        exit(-16);
    }

    funafl_parse_cjson(afl, json, 1);

    cJSON_Delete(json);  // Free the cJSON object
}

void read_loc2bbs(struct afl_state* afl, u8* target_path) {
    char file_path[256], dir_path[256], base_name[256];

    // split target_path into dir_path and base_name
    split_path(target_path, dir_path, base_name);

    snprintf(file_path, sizeof(file_path), "%s/aicfg/%s%s", 
        dir_path, base_name, "_loc2addrs.json");

    cJSON *json = readin_json_file(file_path);
    if (json == NULL) {
        fprintf(stderr, "Failed to read JSON file %s\n", file_path);
        fprintf(stderr, "target_path: %s\n", target_path);
        fprintf(stderr, "dir_path: %s\n", dir_path);
        fprintf(stderr, "base_name: %s\n", base_name);
        exit(-16);
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
    struct score_union* sc = (struct score_union*)calloc(1, sizeof(struct score_union));
    sc->seed_score = cur_bb->score_seed;
    sc->energy_score = cur_bb->score_energy;

    return sc;
}


struct score_union* funafl_get_score_with_loc_and_update_function_count(struct afl_state* afl,
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
            if (afl->debug)
                fprintf(stderr, "[Error] loc2bbs not found for loc=%d\n", loc);
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

    // calculate average score
    if (afl->number_score == 0) {
        fprintf(stderr, "<afl-fuzz-json> Error: number_score is 0\n");
        exit(-4);
    }
    if (afl->number_score_energy == 0) {
        fprintf(stderr, "<afl-fuzz-json> Error: number_score_energy is 0\n");
        exit(-4);
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

    ++afl->number_score;
    ++afl->number_score_energy;
    if (afl->number_score > 2147483600 || afl->number_score_energy > 2147483600) {
        fprintf(stderr, "Error: score overflow\n");
        afl->number_score = 1;
        afl->number_score_energy = 1;
    }

    return res;
}
