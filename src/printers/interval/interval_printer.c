#include "iaprof.h"

#include "printers/stack/stack_printer.h"
#include "printers/debug/debug_printer.h"
#include "printers/flamegraph/flamegraph_printer.h"
#include "stores/interval_profile.h"
#include "collectors/debug/debug_collector.h"
#include "utils/utils.h"
#include "printers/interval/interval_printer.h"

#undef WARN
#define WARN(...) ;

#include <string.h>

static const char *unknown_file = "[unknown file]";
static const char *system_routine = "System Routine (Exceptions)";
static const char *failed_decode = "[failed decode]";

/* String IDs for constant strings */
static uint64_t unknown_file_id = 0;
static uint64_t system_routine_id = 0;
uint64_t failed_decode_id = 0;
static uint64_t active_stall_id = 0;
static uint64_t control_stall_id = 0;
static uint64_t pipestall_stall_id = 0;
static uint64_t send_stall_id = 0;
static uint64_t dist_acc_stall_id = 0;
static uint64_t sbid_stall_id = 0;
static uint64_t sync_stall_id = 0;
static uint64_t inst_fetch_stall_id = 0;
static uint64_t other_stall_id = 0;
static uint64_t unknown_stall_id = 0;

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
                hash_table_insert(string_writer, NULL, 0);
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

        if (id == 0) {
                return "<missing string>";
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

        if (!insert_string_id(id, stack_str)) {
                free(stack_str);
        }
        return 0;
}

int parse_eustall(char *str, void *result)
{
        int retval;
        struct eustall_result *res = (struct eustall_result *)result;

        retval = sscanf(str, "\t%lu\t%u\t%lu\t%lu\t%d\t%d\t%lu\t%lu\t%lu\t%lu\t0x%lx\t%lu",
                        &(res->proc_name_id), &(res->pid), &(res->ustack_id), &(res->kstack_id),
                        &(res->is_debug), &(res->is_sys), &(res->gpu_file_id),
                        &(res->gpu_symbol_id), &(res->insn_text_id), &(res->stall_type_id),
                        &(res->samp_offset), &(res->samp_count));
        if (retval != 12) {
                WARN("eustall line failed to parse!\n");
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

uint64_t print_string(const char *stack_str)
{
        uint64_t id;
        if (!insert_string((char *)stack_str, &id)) {
                return id;
        }
        printf("string\t%lu\t%s\n", id, stack_str);
        fflush(stdout);
        return id;
}

void print_initial_strings()
{
        /* Constant strings */
        unknown_file_id = print_string(unknown_file);
        system_routine_id = print_string(system_routine);
        failed_decode_id = print_string(failed_decode);

        /* Stall types */
        active_stall_id = print_string("active");
        control_stall_id = print_string("control");
        pipestall_stall_id = print_string("pipestall");
        send_stall_id = print_string("send");
        dist_acc_stall_id = print_string("dist_acc");
        sbid_stall_id = print_string("sbid");
        sync_stall_id = print_string("sync");
        inst_fetch_stall_id = print_string("inst_fetch");
        other_stall_id = print_string("other");
        unknown_stall_id = print_string("unknown");

}

void print_eustall(struct sample *samp, uint64_t *countp)
{
        char gpu_symbol_tmp[MAX_GPU_SYMBOL_LEN];

        uint64_t proc_name_id, gpu_file_id, gpu_symbol_id, insn_text_id, stall_type_id;

        proc_name_id = print_string(samp->proc_name);

        /* Ensure we've got a GPU symbol */
        gpu_file_id = 0;
        gpu_symbol_id = 0;
        debug_get_sym(samp->pid, samp->addr, &gpu_symbol_id, &gpu_file_id);

        /* Construct a string to print out for the file of the GPU code */
        if (!gpu_file_id) {
                gpu_file_id = unknown_file_id;
        }

        /* Construct a string to print for the GPU symbol (and line, if applicable) */
        if (!gpu_symbol_id) {
                if (samp->is_sys) {
                        gpu_symbol_id = system_routine_id;
                } else {
                        snprintf(gpu_symbol_tmp, MAX_GPU_SYMBOL_LEN, "0x%lx", samp->addr);
                        gpu_symbol_id = print_string(gpu_symbol_tmp);
                }
        }

        if (samp->insn_id) {
                insn_text_id = samp->insn_id;
        } else {
                insn_text_id = failed_decode_id;
        }

        /* Construct a string for the stall reason */
        switch (samp->stall_type) {
                case STALL_TYPE_ACTIVE:     stall_type_id = active_stall_id;     break;
                case STALL_TYPE_CONTROL:    stall_type_id = control_stall_id;    break;
                case STALL_TYPE_PIPESTALL:  stall_type_id = pipestall_stall_id;  break;
                case STALL_TYPE_SEND:       stall_type_id = send_stall_id;       break;
                case STALL_TYPE_DIST_ACC:   stall_type_id = dist_acc_stall_id;   break;
                case STALL_TYPE_SBID:       stall_type_id = sbid_stall_id;       break;
                case STALL_TYPE_SYNC:       stall_type_id = sync_stall_id;       break;
                case STALL_TYPE_INST_FETCH: stall_type_id = inst_fetch_stall_id; break;
                case STALL_TYPE_OTHER:      stall_type_id = other_stall_id;      break;
                default:
                        stall_type_id = unknown_stall_id;
                        break;
        }

        printf("eustall\t%lu\t%u\t%lu\t%lu\t%d\t%d\t%lu\t%lu\t%lu\t%lu\t0x%lx\t%lu\n",
               proc_name_id, samp->pid,
               get_id(samp->ustack_str), get_id(samp->kstack_str),
               samp->is_debug, samp->is_sys, gpu_file_id,
               gpu_symbol_id, insn_text_id, stall_type_id, samp->offset,
               *countp);
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
