/*
Copyright 2025 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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

/* Globals for keeping track of the state */
static uint64_t cur_proc_name_id,
                cur_pid,
                cur_ustack_id,
                cur_kstack_id,
                cur_gpu_file_id,
                cur_gpu_symbol_id,
                cur_insn_text_id;
int cur_shader_type;

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

int parse_proc_name(char *str, void *result)
{
        unsigned long proc_name_id;
        int retval;
        
        retval = sscanf(str, "\t%lu", &proc_name_id);
        if (retval != 1) {
                WARN("proc_name line failed to parse!\n");
                return -1;
        }
        cur_proc_name_id = proc_name_id;

        return 0;
}

int parse_pid(char *str, void *result)
{
        unsigned pid;
        int retval;
        
        retval = sscanf(str, "\t%u", &pid);
        if (retval != 1) {
                WARN("pid line failed to parse!\n");
                return -1;
        }
        cur_pid = pid;

        return 0;
}

int parse_ustack(char *str, void *result)
{
        unsigned long ustack_id;
        int retval;
        
        retval = sscanf(str, "\t%lu", &ustack_id);
        if (retval != 1) {
                WARN("ustack line failed to parse!\n");
                return -1;
        }
        cur_ustack_id = ustack_id;

        return 0;
}

int parse_kstack(char *str, void *result)
{
        unsigned long kstack_id;
        int retval;
        
        retval = sscanf(str, "\t%lu", &kstack_id);
        if (retval != 1) {
                WARN("kstack line failed to parse!\n");
                return -1;
        }
        cur_kstack_id = kstack_id;

        return 0;
}

int parse_shader_type(char *str, void *result)
{
        int shader_type;
        int retval;
        
        retval = sscanf(str, "\t%d", &shader_type);
        if (retval != 1) {
                WARN("shader_type line failed to parse!\n");
                return -1;
        }
        cur_shader_type = shader_type;

        return 0;
}

int parse_gpu_file(char *str, void *result)
{
        unsigned long gpu_file_id;
        int retval;
        
        retval = sscanf(str, "\t%lu", &gpu_file_id);
        if (retval != 1) {
                WARN("gpu_file line failed to parse!\n");
                return -1;
        }
        cur_gpu_file_id = gpu_file_id;

        return 0;
}

int parse_gpu_symbol(char *str, void *result)
{
        unsigned long gpu_symbol_id;
        int retval;
        
        retval = sscanf(str, "\t%lu", &gpu_symbol_id);
        if (retval != 1) {
                WARN("gpu_symbol line failed to parse!\n");
                return -1;
        }
        cur_gpu_symbol_id = gpu_symbol_id;

        return 0;
}

int parse_insn_text(char *str, void *result)
{
        unsigned long insn_text_id;
        int retval;
        
        retval = sscanf(str, "\t%lu", &insn_text_id);
        if (retval != 1) {
                WARN("insn_text line failed to parse!\n");
                return -1;
        }
        cur_insn_text_id = insn_text_id;

        return 0;
}

int parse_eustall(char *str, void *result)
{
        int retval;
        struct eustall_result *res = (struct eustall_result *)result;
        
        retval = sscanf(str, "\t%lu\t%lu\t%lx\t%lu",
                        &(res->overall_stack_id), &(res->stall_type_id), &(res->samp_offset), &(res->samp_count));
        if (retval != 4) {
                WARN("eustall line failed to parse, arguments: '%s'\n", str);
                return -1;
        }
        
        res->proc_name_id = cur_proc_name_id;
        res->pid = cur_pid;
        res->ustack_id = cur_ustack_id;
        res->kstack_id = cur_kstack_id;
        res->shader_type = cur_shader_type;
        res->gpu_file_id = cur_gpu_file_id;
        res->gpu_symbol_id = cur_gpu_symbol_id;
        res->insn_text_id = cur_insn_text_id;

        return 0;
}

int parse_interval_start(char *str, void *result)
{
        int retval;
        struct interval_result *res = (struct interval_result *)result;
        
        if (!result) {
                return 0;
        }
        
        retval = sscanf(str, "\t%lu\t%lf", &(res->num), &(res->time));
        if (retval != 2) {
                WARN("interval_start line failed to parse!\n");
                return -1;
        }
        
        return 0;
}

int parse_interval_end(char *str, void *result)
{
        return 0;
}

static char *profile_event_strs[] = {
  [PROFILE_EVENT_STRING] = "string",
  [PROFILE_EVENT_PROC_NAME] = "proc_name",
  [PROFILE_EVENT_PID] = "pid",
  [PROFILE_EVENT_USTACK] = "ustack",
  [PROFILE_EVENT_KSTACK] = "kstack",
  [PROFILE_EVENT_SHADER_TYPE] = "shader_type",
  [PROFILE_EVENT_GPU_FILE] = "gpu_file",
  [PROFILE_EVENT_GPU_SYMBOL] = "gpu_symbol",
  [PROFILE_EVENT_INSN_TEXT] = "insn_text",
  [PROFILE_EVENT_EUSTALL] = "e",
  [PROFILE_EVENT_INTERVAL_START] = "interval_start",
  [PROFILE_EVENT_INTERVAL_END] = "interval_end",
};

/* Function pointers for each type of profile event.
   Each accepts the string of the line as an argument, and
   returns a void * to their corresponding return type. */
static int (*profile_event_funcs[]) (char *, void *) = {
  [PROFILE_EVENT_STRING] = &parse_string,
  [PROFILE_EVENT_PROC_NAME] = &parse_proc_name,
  [PROFILE_EVENT_PID] = &parse_pid,
  [PROFILE_EVENT_USTACK] = &parse_ustack,
  [PROFILE_EVENT_KSTACK] = &parse_kstack,
  [PROFILE_EVENT_SHADER_TYPE] = &parse_shader_type,
  [PROFILE_EVENT_GPU_FILE] = &parse_gpu_file,
  [PROFILE_EVENT_GPU_SYMBOL] = &parse_gpu_symbol,
  [PROFILE_EVENT_INSN_TEXT] = &parse_insn_text,
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
        insert_string_id(id, (char *)stack_str);
        printf("string\t%lu\t%s\n", id, stack_str);
        fflush(stdout);
        return id;
}

void print_frame()
{
        printf("frame\n");
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

uint64_t get_stall_type_id(int stall_type_enum) {
  
        uint64_t stall_type_id;
        
        /* Construct a string for the stall reason */
        switch (stall_type_enum) {
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
        
        return stall_type_id;
}

void print_insn_text(uint64_t insn_text_id)
{
  if (insn_text_id != cur_insn_text_id) {
    printf("insn_text\t%lu\n", insn_text_id);
    cur_insn_text_id = insn_text_id;
  }
}

void print_gpu_symbol(uint64_t gpu_symbol_id)
{
  if (gpu_symbol_id != cur_gpu_symbol_id) {
    printf("gpu_symbol\t%lu\n", gpu_symbol_id);
    cur_gpu_symbol_id = gpu_symbol_id;
  }
}

void print_ustack(uint64_t ustack_id)
{
  if (ustack_id != cur_ustack_id) {
    printf("ustack\t%lu\n", ustack_id);
    cur_ustack_id = ustack_id;
  }
}

void print_kstack(uint64_t kstack_id)
{
  if (kstack_id != cur_kstack_id) {
    printf("kstack\t%lu\n", kstack_id);
    cur_kstack_id = kstack_id;
  }
}

void print_proc_name(uint64_t proc_name_id)
{
  if (proc_name_id != cur_proc_name_id) {
    printf("proc_name\t%lu\n", proc_name_id);
    cur_proc_name_id = proc_name_id;
  }
}

void print_pid(uint32_t pid)
{
  if (pid != cur_pid) {
    printf("pid\t%u\n", pid);
    cur_pid = pid;
  }
}

void print_gpu_file(uint64_t gpu_file_id)
{
  if (gpu_file_id != cur_gpu_file_id) {
    printf("gpu_file\t%lu\n", gpu_file_id);
    cur_gpu_file_id = gpu_file_id;
  }
}

void print_shader_type(int shader_type) {
  if (shader_type != cur_shader_type) {
    printf("shader_type\t%d\n", shader_type);
    cur_shader_type = shader_type;
  }
}

void print_eustall(struct shader *shader, uint64_t offset, uint64_t insn_text_id, int stall_type, uint64_t count)
{
        char gpu_symbol_tmp[MAX_GPU_SYMBOL_LEN];
        
        int overall_stack_size;
        char *overall_stack;
        
        uint64_t gpu_file_id;
        uint64_t overall_stack_id;

        if (count == 0) { return; }

        gpu_file_id = shader->filename_id;
        if (gpu_file_id == 0) {
                gpu_file_id = unknown_file_id;
        }

        /* Construct a string to print for the GPU symbol (and line, if applicable) */
        if (shader->symbol_id == 0) {
                if (shader->type == SHADER_TYPE_SYSTEM_ROUTINE) {
                        shader->symbol_id = system_routine_id;
                } else {
                        snprintf(gpu_symbol_tmp, MAX_GPU_SYMBOL_LEN, "0x%lx", shader->gpu_addr);
                        shader->symbol_id = print_string(gpu_symbol_tmp);
                }
        }
        
        print_proc_name(shader->proc_name_id);
        print_pid(shader->pid);
        print_ustack(shader->ustack_id);
        print_kstack(shader->kstack_id);
        print_shader_type(shader->type);
        print_gpu_file(gpu_file_id);
        print_gpu_symbol(shader->symbol_id);
        print_insn_text(insn_text_id);

        /* Get the size of the resulting string */
        overall_stack_size = snprintf(NULL, 0, flame_fmt,
          get_string(shader->proc_name_id), shader->pid,
          get_string(shader->ustack_id),
          get_string(shader->kstack_id),
          get_string(gpu_file_id), get_string(shader->symbol_id),
          get_string(insn_text_id), get_string(get_stall_type_id(stall_type)),
          offset) + 1;
        overall_stack = malloc(overall_stack_size * sizeof(char));
        snprintf(overall_stack, overall_stack_size, flame_fmt,
          get_string(shader->proc_name_id), shader->pid,
          get_string(shader->ustack_id),
          get_string(shader->kstack_id),
          get_string(gpu_file_id), get_string(shader->symbol_id),
          get_string(insn_text_id), get_string(get_stall_type_id(stall_type)),
          offset);
        overall_stack_id = print_string(overall_stack);
        free(overall_stack);

        printf("e\t%lu\t%lu\t%lx\t%lu\n",
               overall_stack_id, get_stall_type_id(stall_type), offset, count);
}

void print_eustall_drop(uint64_t addr, int stall_type, uint64_t count)
{
        char gpu_symbol_tmp[MAX_GPU_SYMBOL_LEN];
        uint64_t gpu_symbol_id;
        
        int overall_stack_size;
        char *overall_stack;
        uint64_t overall_stack_id;

        if (count == 0) { return; }

        snprintf(gpu_symbol_tmp, MAX_GPU_SYMBOL_LEN, "0x%lx", addr);
        gpu_symbol_id = print_string(gpu_symbol_tmp);
        
        print_proc_name(0);
        print_pid(0);
        print_ustack(0);
        print_kstack(0);
        print_shader_type(0);
        print_gpu_file(unknown_file_id);
        print_gpu_symbol(gpu_symbol_id);
        print_insn_text(failed_decode_id);
        
        /* Get the size of the resulting string */
        overall_stack_size = snprintf(NULL, 0, flame_fmt,
          get_string(0), 0,
          get_string(0),
          get_string(0),
          get_string(unknown_file_id), get_string(gpu_symbol_id),
          get_string(failed_decode_id), get_string(get_stall_type_id(stall_type)),
          0) + 1;
        overall_stack = malloc(overall_stack_size * sizeof(char));
        snprintf(overall_stack, overall_stack_size, flame_fmt,
          get_string(0), 0,
          get_string(0),
          get_string(0),
          get_string(unknown_file_id), get_string(gpu_symbol_id),
          get_string(failed_decode_id), get_string(get_stall_type_id(stall_type)),
          0);
        overall_stack_id = print_string(overall_stack);
        free(overall_stack);

        printf("e\t%lu\t%lu\t%lx\t%lu\n",
               overall_stack_id, get_stall_type_id(stall_type), 0ul, count);
}

/* Returns 0 on success, -1 for failure */
static char get_insn_text(struct shader *shader, uint64_t offset,
                   char **insn_text, size_t *insn_text_len)
{
        char retval;

        retval = 0;

        /* Paranoid check */
        if (offset >= shader->size) {
                if (debug) {
                        WARN("Got an EU stall past the end of a buffer. offset=0x%lx size=%lu\n", offset, shader->size);
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
        int                    have_binary;
        uint64_t               offset;
        struct offset_profile *profile;
        char                  *insn_text;
        size_t                 insn_text_len;
        uint64_t               insn_text_id;
        int                    stall_type;
        uint64_t               count;
        
        have_binary = 0;
        
        if (shader->binary != NULL && shader->size > 0) {
                have_binary = 1;
        } else {
                if (debug) {
                        WARN("Don't have a copy of the shader's binary at 0x%lx\n", shader->gpu_addr);
                }
        }

        /* Iterate over the offsets that we have EU stalls for */
        hash_table_traverse(shader->stall_counts, offset, profile) {
                /* Disassemble to get the instruction */
                insn_text = NULL;
                insn_text_len = 0;
                
                if (!have_binary || get_insn_text(shader, offset, &insn_text, &insn_text_len) != 0) {
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

/***************************************
* Intervals
*
* Stores strings that we want to print out and assigns
* a unique ID to them.
***************************************/

void print_interval(uint64_t interval, array_t *waitlist)
{
        struct shader *shader;
        struct timespec tspec;
        double time;
        
        clock_gettime(CLOCK_MONOTONIC, &tspec);
        time = ((double)tspec.tv_sec) + ((double)tspec.tv_nsec / 1000000000);
        
        printf("interval_start\t%lu\t%.6lf\n", interval, time);

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
