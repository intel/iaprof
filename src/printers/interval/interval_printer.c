#include "iaprof.h"

#include "printers/stack/stack_printer.h"
#include "printers/debug/debug_printer.h"
#include "stores/gpu_kernel.h"
#include "collectors/eustall/eustall_collector.h"
#include "collectors/debug/debug_collector.h"
#include "utils/utils.h"
#include "printers/interval/interval_printer.h"
#include "gpu_parsers/shader_decoder.h"

#include <string.h>
#include <pthread.h>


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
static pthread_mutex_t string_writer_lock = PTHREAD_MUTEX_INITIALIZER;

/* Inserts a string into the hash table, returns 1 if it
   had to be inserted. Fills *id with the new ID. */
int insert_string(char *str, uint64_t *id)
{
        uint64_t *lookup;

        pthread_mutex_lock(&string_writer_lock);

        if (string_writer == NULL) {
                if (string_writer == NULL) {
                        string_writer = hash_table_make(string, uint64_t, str_hash);
                        hash_table_insert(string_writer, NULL, 0);
                }
        }
        lookup = hash_table_get_val(string_writer, str);
        if (lookup != NULL) {
                *id = *lookup;
                pthread_mutex_unlock(&string_writer_lock);
                return 0;
        }
        *id = cur_id;
        hash_table_insert(string_writer, strdup(str), cur_id++);

        pthread_mutex_unlock(&string_writer_lock);

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
        pthread_mutex_lock(&string_writer_lock);
        lookup = hash_table_get_val(string_writer, (char *)str);
        if (lookup != NULL) {
                pthread_mutex_unlock(&string_writer_lock);
                return *lookup;
        }
        pthread_mutex_unlock(&string_writer_lock);
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

void print_eustall(struct shader *shader, uint64_t offset, uint64_t insn_text_id, int stall_type, uint64_t count)
{
        char gpu_symbol_tmp[MAX_GPU_SYMBOL_LEN];

        uint64_t gpu_file_id, gpu_symbol_id, stall_type_id;

        if (count == 0) { return; }

        /* Ensure we've got a GPU symbol */
        gpu_file_id   = shader->filename_id;
        gpu_symbol_id = shader->symbol_id;

        /* Construct a string to print out for the file of the GPU code */
        if (gpu_file_id == 0) {
                gpu_file_id = unknown_file_id;
        }

        /* Construct a string to print for the GPU symbol (and line, if applicable) */
        if (gpu_symbol_id == 0) {
                if (shader->type == SHADER_TYPE_SYSTEM_ROUTINE) {
                        gpu_symbol_id = system_routine_id;
                } else {
                        snprintf(gpu_symbol_tmp, MAX_GPU_SYMBOL_LEN, "0x%lx", shader->gpu_addr);
                        gpu_symbol_id = print_string(gpu_symbol_tmp);
                }
        }

        /* Construct a string for the stall reason */
        switch (stall_type) {
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
               shader->proc_name_id, shader->pid,
               shader->ustack_id, shader->kstack_id,
               shader->type == SHADER_TYPE_DEBUG_AREA, shader->type == SHADER_TYPE_SYSTEM_ROUTINE, gpu_file_id,
               gpu_symbol_id, insn_text_id, stall_type_id, offset,
               count);
}

void print_eustall_drop(uint64_t addr, int stall_type, uint64_t count)
{
        char gpu_symbol_tmp[MAX_GPU_SYMBOL_LEN];
        uint64_t gpu_symbol_id;
        uint64_t stall_type_id;

        if (count == 0) { return; }

        snprintf(gpu_symbol_tmp, MAX_GPU_SYMBOL_LEN, "0x%lx", addr);
        gpu_symbol_id = print_string(gpu_symbol_tmp);

        /* Construct a string for the stall reason */
        switch (stall_type) {
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
               0ul, 0,
               0ul, 0ul,
               0, 0, unknown_file_id,
               gpu_symbol_id, failed_decode_id, stall_type_id, 0ul,
               count);
}

/* Returns 0 on success, -1 for failure */
static char get_insn_text(struct shader *shader, uint64_t offset,
                   char **insn_text, size_t *insn_text_len)
{
        char retval;

        retval = 0;

        if (shader->binary == NULL || shader->size == 0) {
                if (debug) {
                        WARN("Don't have a copy of the shader's binary at 0x%lx\n", shader->gpu_addr);
                }
                retval = -1;
                goto out;
        }

        /* Paranoid check */
        if (offset >= shader->size) {
                if (debug) {
                        WARN("Got an EU stall past the end of a buffer. ");
                        fprintf(stderr, "offset=0x%lx size=%lu\n", offset, shader->size);
                }
                retval = -1;
                goto out;
        }

        /* Initialize the kernel view */
        if (!shader->kv) {
                shader->kv = iga_init(shader->binary, shader->size);
                if (!shader->kv) {
                        if (debug) {
                                WARN("Failed to initialize IGA.\n");
                        }
                        retval = -1;
                        goto out;
                }
        }

        /* Disassemble */
        retval = iga_disassemble_insn(shader->kv, offset, insn_text,
                                      insn_text_len);
        if (retval != 0) {
                if (debug) {
                        WARN("Disassembly failed on shader at 0x%lx\n", shader->gpu_addr);
                }
                goto out;
        }

out:;
        return retval;
}

void print_unknown_samples(array_t *waitlist) {
        struct deferred_eustall *it;
        uint64_t                 addr;

        array_traverse(*waitlist, it) {
                addr = ((uint64_t)it->sample.ip) << 3;

                print_eustall_drop(addr, STALL_TYPE_ACTIVE,     it->sample.active);
                print_eustall_drop(addr, STALL_TYPE_CONTROL,    it->sample.control);
                print_eustall_drop(addr, STALL_TYPE_PIPESTALL,  it->sample.pipestall);
                print_eustall_drop(addr, STALL_TYPE_SEND,       it->sample.send);
                print_eustall_drop(addr, STALL_TYPE_DIST_ACC,   it->sample.dist_acc);
                print_eustall_drop(addr, STALL_TYPE_SBID,       it->sample.sbid);
                print_eustall_drop(addr, STALL_TYPE_SYNC,       it->sample.sync);
                print_eustall_drop(addr, STALL_TYPE_INST_FETCH, it->sample.inst_fetch);
                print_eustall_drop(addr, STALL_TYPE_OTHER,      it->sample.other);
#if GPU_DRIVER == GPU_DRIVER_xe
                print_eustall_drop(addr, STALL_TYPE_TDR,        it->sample.tdr);
#endif
        }
}

void print_kernel_profile(struct shader *shader)
{
        uint64_t               offset;
        struct offset_profile *profile;
        char                  *insn_text;
        size_t                 insn_text_len;
        char                   retval;
        uint64_t               insn_text_id;
        int                    stall_type;
        uint64_t               count;


        /* Iterate over the offsets that we have EU stalls for */
        hash_table_traverse(shader->stall_counts, offset, profile) {
                /* Disassemble to get the instruction */
                insn_text = NULL;
                insn_text_len = 0;

                retval = get_insn_text(shader, offset, &insn_text, &insn_text_len);
                if (retval != 0) {
                        insn_text_id = failed_decode_id;
                } else {
                        insn_text_id = print_string(insn_text);
                }

                for (stall_type = 0; stall_type < NR_STALL_TYPES; stall_type += 1) {
                        count = profile->counts[stall_type];
                        if (count > 0) {
                                print_eustall(shader, offset, insn_text_id, stall_type, count);
                        }
                }

                if (insn_text_id != failed_decode_id) {
                        free(insn_text);
                }
        }
}

void print_interval(uint64_t interval, array_t *waitlist)
{
        struct shader *shader;

        printf("interval_start\t%lu\n", interval);

        FOR_SHADER(shader, {
                if (shader->stall_counts == NULL) { continue; }

                print_kernel_profile(shader);
        });

        if (waitlist != NULL) {
                print_unknown_samples(waitlist);
        }

        printf("interval_end\t%lu\n", interval);
        fflush(stdout);
}
