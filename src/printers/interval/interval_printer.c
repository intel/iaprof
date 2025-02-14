#include "iaprof.h"

#include "printers/stack/stack_printer.h"
#include "printers/debug/debug_printer.h"
#include "printers/flamegraph/flamegraph_printer.h"
#include "stores/interval_profile.h"
#include "collectors/debug_i915/debug_i915_collector.h"
#include "utils/utils.h"
#include "printers/interval/interval_printer.h"

#include <string.h>

static const char *unknown_file = "[unknown file]";
static const char *system_routine = "System Routine (Exceptions)";
static const char *failed_decode = "[failed decode]";

/***************************************
* String Table
*
* Stores strings that we want to print out and assigns
* a unique ID to them.
***************************************/

static uint64_t cur_id = 1;
typedef char *string;
use_hash_table(uint64_t, string);
use_hash_table_e(string, uint64_t, str_equ);
static hash_table(string, uint64_t) string_writer;
static hash_table(uint64_t, string) string_reader;

/* Inserts a string into the hash table, returns 1 if it
   had to be inserted. Fills *id with the new ID. */
int insert_string(char *str, uint64_t *id)
{
        uint64_t *lookup;
        
        if (string_writer == NULL) {
                string_writer = hash_table_make(string, uint64_t, str_hash);
        }
        lookup = hash_table_get_val(string_writer, str);
        if (lookup != NULL) {
                *id = *lookup;
                return 0;
        }
        *id = cur_id;
        hash_table_insert(string_writer, str, cur_id++);
        return 1;
}

int insert_string_id(uint64_t id, char *str)
{
        char **lookup;
        
        if (string_reader == NULL) {
                string_reader = hash_table_make(uint64_t, string, noop_hash);
        }
        lookup = hash_table_get_val(string_reader, id);
        if (lookup == NULL) {
                hash_table_insert(string_reader, id, str);
                return 1;
        }
        return 0;
}

char *get_string(uint64_t id)
{
        char **lookup;
        
        if (string_reader == NULL) {
                return NULL;
        }
        lookup = hash_table_get_val(string_reader, id);
        if (lookup == NULL) {
                return NULL;
        }
        return *lookup;
}

uint64_t get_id(const char *str)
{
        uint64_t *lookup;
        
        if ((string_writer == NULL) ||
            (str == NULL)) {
                return 0;
        }
        lookup = hash_table_get_val(string_writer, (char *)str);
        if (lookup != NULL) {
                return *lookup;
        }
        return 0;
}

int parse_string(char *str, void *result)
{
        char *token;
        int token_index;
        
        char *stack_str;
        uint64_t id;
        uint64_t *size = result;
        
        token_index = 0;
        token = strtok(str, "\t");
        while (token != NULL) {
                
                /* The first token is the string ID */
                if (token_index == 0) {
                        if (sscanf(token, "%lu", &id) != 1) {
                                WARN("stack line failed to parse a string ID from: %s\n", token);
                                return -1;
                        }
                        token = strtok(NULL, "\t");
                        token_index++;
                        
                /* The rest of the string is the stack string */
                } else if (token_index == 1) {
                        if(sscanf(token, "%m[^\t]", &stack_str) != 1) {
                                WARN("Couldn't parse this as a stack string: %s\n", token);
                                return -1;
                        }
                        token_index++;
                        break;
                }
        }
        
        /* Sanity-check */
        if (token_index < 2) {
                WARN("stack line got too few tab-delimited tokens\n");
                return -1;
        } else if (token_index > 2) {
                WARN("stack line got too many tab-delimited tokens\n");
                return -1;
        }
        
        *size = strlen(stack_str);
        
        if (!insert_string_id(id, stack_str)) {
                free(stack_str);
        }
        return 0;
}

int parse_eustall(char *str, void *result)
{
        char *token;
        int token_index;
        struct eustall_result *res = (struct eustall_result *)result;
        
        uint64_t ustack_id, kstack_id;
        
        token_index = 0;
        token = strtok(str, "\t");
        while (token != NULL) {
                
                if (token_index == 0) {
                        if(sscanf(token, "%s", res->proc_name) != 1) {
                                WARN("eustall line failed to parse this as a process name: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 1) {
                        if (sscanf(token, "%u", &(res->pid)) != 1) {
                                WARN("eustall line failed to parse a PID from: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 2) {
                        if (sscanf(token, "%lu", &ustack_id) != 1) {
                                WARN("eustall line failed to parse a string ID from: %s\n", token);
                                return -1;
                        }
                        res->ustack_str = get_string(ustack_id);
                } else if (token_index == 3) {
                        if (sscanf(token, "%lu", &kstack_id) != 1) {
                                WARN("eustall line failed to parse a string ID from: %s\n", token);
                                return -1;
                        }
                        res->kstack_str = get_string(kstack_id);
                } else if (token_index == 4) {
                        if (sscanf(token, "%d", &(res->is_debug)) != 1) {
                                WARN("eustall line failed to parse an int from: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 5) {
                        if (sscanf(token, "%d", &(res->is_sys)) != 1) {
                                WARN("eustall line failed to parse an int from: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 6) {
                        if(sscanf(token, "%s", res->gpu_file) != 1) {
                                WARN("eustall line failed to parse this as a string: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 7) {
                        if(sscanf(token, "%s", res->gpu_symbol) != 1) {
                                WARN("eustall line failed to parse this as a string: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 8) {
                        if(sscanf(token, "%s", res->insn_text) != 1) {
                                WARN("eustall line failed to parse this as a string: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 9) {
                        if(sscanf(token, "%s", res->stall_type_str) != 1) {
                                WARN("eustall line failed to parse this as a string: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 10) {
                        if (sscanf(token, "0x%lx", &(res->samp_offset)) != 1) {
                                WARN("eustall line failed to parse a value from: %s\n", token);
                                return -1;
                        }
                } else if (token_index == 11) {
                        if (sscanf(token, "%lu", &(res->samp_count)) != 1) {
                                WARN("eustall line failed to parse a value from: %s\n", token);
                                return -1;
                        }
                        token = strtok(NULL, "\t");
                        token_index++;
                        break;
                }
                
                /* Advance to the next tab-delimited field */
                token = strtok(NULL, "\t");
                token_index++;
        }
        
        /* Sanity-check */
        if (token_index < 12) {
                WARN("eustall line got too few tab-delimited tokens\n");
                return -1;
        } else if (token_index > 12) {
                WARN("eustall line got too many tab-delimited tokens\n");
                return -1;
        }
        
        return 0;
}

int parse_interval_start(char *str, void *result)
{
        return 0;
}

int parse_interval_end(char *str, void *result)
{
        return 0;
}

static char *profile_event_strs[] = {
  [PROFILE_EVENT_STRING] = "string",
  [PROFILE_EVENT_EUSTALL] = "eustall",
  [PROFILE_EVENT_INTERVAL_START] = "interval_start",
  [PROFILE_EVENT_INTERVAL_END] = "interval_end",
};

/* Function pointers for each type of profile event.
   Each accepts the string of the line as an argument, and
   returns a void * to their corresponding return type. */
static int (*profile_event_funcs[]) (char *, void *) = {
  [PROFILE_EVENT_STRING] = &parse_string,
  [PROFILE_EVENT_EUSTALL] = &parse_eustall,
  [PROFILE_EVENT_INTERVAL_START] = &parse_interval_start,
  [PROFILE_EVENT_INTERVAL_END] = &parse_interval_end,
};

/* Given a string of a line, parses the profile event on that line, and
   returns the size of the event name, a function pointer to parse it, and the profile_event enum value. */
int get_profile_event_func(char *str, size_t *size, int (**func_ptr)(char *, void *), enum profile_event *event)
{
        int i;
        
        for (i = 0; i < PROFILE_EVENT_MAX; i++) {
                *size = strlen(profile_event_strs[i]);
                if (strncmp(str, profile_event_strs[i], *size) == 0) {
                        *event = i;
                        *func_ptr = profile_event_funcs[i];
                        return 0;
                }
        }
        return -1;
}

void print_string(const char *stack_str)
{
        uint64_t id;
        if (!insert_string((char *)stack_str, &id)) {
                return;
        }
        printf("string\t%lu\t%s\n", id, stack_str);
        fflush(stdout);
}

void print_eustall(struct sample *samp, uint64_t *countp)
{
        char               *gpu_symbol;
        char               *gpu_file;
        int                 gpu_line;
        int                 err;
        const char         *stall_type_str;
        char                symbol_and_line[MAX_GPU_SYMBOL_LEN];
        
        /* Ensure we've got a GPU symbol */
        err = debug_i915_get_sym(samp->pid, samp->addr, &gpu_symbol, &gpu_file, &gpu_line);
        if (err) {
                gpu_symbol = NULL;
                gpu_file   = NULL;
                gpu_line   = 0;
        }

        printf("eustall\t%.*s\t%u\t%lu\t%lu\t%d\t%d\t",
               MAX_PROC_NAME_LEN, samp->proc_name, samp->pid,
               get_id(samp->ustack_str), get_id(samp->kstack_str),
               samp->is_debug, samp->is_sys);
               
        /* Print a maximum of MAX_GPU_FILE_LEN characters for the GPU filename */
        if (gpu_file) {
                printf("%.*s\t", MAX_GPU_FILE_LEN, gpu_file);
        } else {
                printf("%.*s\t", MAX_GPU_FILE_LEN, unknown_file);
        }
        
        /* Print a maximum of MAX_GPU_SYMBOL_LEN characters for the GPU symbol */
        if (gpu_symbol) {
                if (gpu_line) {
                        snprintf(symbol_and_line, MAX_GPU_SYMBOL_LEN,
                                 "%s line %d", gpu_symbol, gpu_line);
                        printf("%.*s\t", MAX_GPU_SYMBOL_LEN, symbol_and_line);
                } else {
                        printf("%.*s\t", MAX_GPU_SYMBOL_LEN, gpu_symbol);
                }
        } else if (samp->is_sys) {
                printf("%.*s\t", MAX_GPU_SYMBOL_LEN, system_routine);
        } else {
                printf("0x%lx\t", samp->addr);
        }
        
        /* Print a maximum of MAX_INSN_TEXT_LEN for the instruction text */
        if (samp->insn_text) {
                printf("%.*s\t", MAX_INSN_TEXT_LEN, samp->insn_text);
        } else {
                printf("%.*s\t", MAX_INSN_TEXT_LEN, failed_decode);
        }

        switch (samp->stall_type) {
                case STALL_TYPE_ACTIVE:     stall_type_str = "active";     break;
                case STALL_TYPE_CONTROL:    stall_type_str = "control";    break;
                case STALL_TYPE_PIPESTALL:  stall_type_str = "pipestall";  break;
                case STALL_TYPE_SEND:       stall_type_str = "send";       break;
                case STALL_TYPE_DIST_ACC:   stall_type_str = "dist_acc";   break;
                case STALL_TYPE_SBID:       stall_type_str = "sbid";       break;
                case STALL_TYPE_SYNC:       stall_type_str = "sync";       break;
                case STALL_TYPE_INST_FETCH: stall_type_str = "inst_fetch"; break;
                case STALL_TYPE_OTHER:      stall_type_str = "other";      break;
                default:
                        stall_type_str = "unknown";
                        break;
        }
        
        /* Print a maximum of MAX_STALL_TYPE_LEN for the stall type */
        printf("%.*s\t", MAX_STALL_TYPE_LEN, stall_type_str);
        printf("0x%lx\t", samp->offset);
        printf("%lu\n", *countp);
        fflush(stdout);
}

void print_interval(uint64_t interval)
{
        struct sample      samp;
        uint64_t           *countp;
        
        printf("interval_start\t%lu\n", interval);

        hash_table_traverse(interval_profile, samp, countp) {
                print_eustall(&samp, countp);
        }
        
        printf("interval_end\t%lu\n", interval);
        fflush(stdout);
}
