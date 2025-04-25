#include "commands/flame.h"
#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"
#include "utils/hash_table.h"
#include "utils/utils.h"

typedef struct eustall_result euresult;

int flame_equ(euresult a, euresult b)
{
        if ((a.proc_name_id != b.proc_name_id) ||
            (a.gpu_file_id != b.gpu_file_id) ||
            (a.gpu_symbol_id != b.gpu_symbol_id) ||
            (a.insn_text_id != b.insn_text_id) ||
            (a.stall_type_id != b.stall_type_id) ||
            (a.ustack_id != b.ustack_id) ||
            (a.kstack_id != b.kstack_id) ||
            (a.pid != b.pid) ||
            (a.samp_offset != b.samp_offset) ||
            (a.is_debug != b.is_debug) ||
            (a.is_sys != b.is_sys)) {
                return 0;
        }
        return 1;
}
static uint64_t flame_hash(const euresult result) {
        uint64_t hash;

        hash = 2654435761ULL;

        hash *= result.ustack_id;
        hash *= result.kstack_id;
        hash ^= result.proc_name_id;
        hash ^= (uint64_t)result.pid << 8;
        hash ^= result.gpu_file_id << 16;
        hash ^= result.gpu_symbol_id << 24;
        hash ^= result.insn_text_id << 32;
        hash ^= result.stall_type_id << 40;
        hash ^= result.samp_offset << 48;

        return hash;
}

use_hash_table_e(euresult, uint64_t, flame_equ);
static hash_table(euresult, uint64_t) flame_counts;

/* The format for the full stack on a line of flame graph output. */
static const char *flame_fmt = "%s;%u;%s%s-;%s_[G];%s_[G];%s_[g];%s_[g];0x%lx_[g]; %lu\n";
#define INITIAL_MAX_STACK_LEN 4096

static FILE *input_file = NULL;
static FILE *fuzz_file = NULL;
static int fuzzing = 0;

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    fuzzing = 1;

    fuzz_file = fmemopen((char*)data, size, "r");

    flame(0, NULL);

    return 0;
}

void flame(int argc, char **argv)
{
        ssize_t bytes_read;
        size_t line_size, size;

        enum profile_event event;
        char *line_buffer;
        int (*func) (char *, void *);

        int retval;
        struct eustall_result result;

        uint64_t *lookup;

        flame_counts = hash_table_make(euresult, uint64_t, flame_hash);

        input_file = fuzzing ? fuzz_file : stdin;
        if (input_file == NULL) { return; }

        line_buffer = NULL;
        line_size = 0;
        while ((bytes_read = getline(&line_buffer, &line_size, input_file)) != -1) {
                /* Remove the newline */
                if (line_buffer[bytes_read - 1] == '\n') {
                        line_buffer[bytes_read - 1] = '\0';
                }

                retval = get_profile_event_func(line_buffer, &size, &func, &event);
                if (retval != 0) {
                        if (!fuzzing) {
                                WARN("Unrecognized input line: '%s'\n", line_buffer);
                        }
                        continue;
                }

                /* Parse the line by calling the function pointer */
                if (event == PROFILE_EVENT_EUSTALL) {
                        retval = (*func)(line_buffer + size, &result);
                } else if (event == PROFILE_EVENT_STRING) {
                        retval = (*func)(line_buffer + size, NULL);
                } else {
                        retval = (*func)(line_buffer + size, NULL);
                }

                if (retval) {
                        if (!fuzzing) {
                                WARN("There was an error parsing a profile event: '%s'\n", line_buffer);
                        }
                        continue;
                } else if (event != PROFILE_EVENT_EUSTALL) {
                        continue;
                }

                lookup = hash_table_get_val(flame_counts, result);
                if (lookup != NULL) {
                        *lookup += result.samp_count;
                } else {
                        hash_table_insert(flame_counts, result, result.samp_count);
                }
        }

        if (line_buffer != NULL) {
            free(line_buffer);
        }

        if (!fuzzing) {
            hash_table_traverse(flame_counts, result, lookup) {
                    printf(flame_fmt, get_string(result.proc_name_id), result.pid,
                        result.ustack_id ? get_string(result.ustack_id) : "",
                        result.kstack_id ? get_string(result.kstack_id) : "",
                        get_string(result.gpu_file_id), get_string(result.gpu_symbol_id),
                        get_string(result.insn_text_id), get_string(result.stall_type_id),
                        result.samp_offset, *lookup);
            }
        }

        hash_table_free(flame_counts);
}
