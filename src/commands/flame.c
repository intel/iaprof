#include "commands/flame.h"
#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"
#include "utils/hash_table.h"
#include "utils/utils.h"

typedef char *string;
use_hash_table_e(string, uint64_t, str_equ);
static hash_table(string, uint64_t) flame_counts;

/* The format for the full stack on a line of flame graph output. */
static const char *flame_fmt = "%s;%u;%s%s-;%s_[G];%s_[G];%s_[g];%s_[g];0x%lx_[g];";
#define INITIAL_MAX_STACK_LEN 4096

void flame(int argc, char **argv)
{
        ssize_t bytes_read;
        size_t line_size, size;
        
        enum profile_event event;
        char *line_buffer;
        int (*func) (char *, void *);
        
        int retval;
        struct eustall_result result;
        uint64_t string_size, max_string_size;
        
        int cur_output_line_size,
            needed_output_line_size;
        char *output_line, *tmp;
        uint64_t *lookup;
        
        flame_counts = hash_table_make(string, uint64_t, str_hash);
        
        /* Calculate the buffer that we need to pre-allocate in order to accommodate for
           the longest output line that we'll see. */
        needed_output_line_size = strlen(flame_fmt)
                                  + MAX_PROC_NAME_LEN
                                  + MAX_PID_LEN
                                  + INITIAL_MAX_STACK_LEN
                                  + INITIAL_MAX_STACK_LEN
                                  + MAX_GPU_FILE_LEN
                                  + MAX_GPU_SYMBOL_LEN
                                  + MAX_INSN_TEXT_LEN
                                  + MAX_STALL_TYPE_LEN
                                  + MAX_OFFSET_LEN
                                  + 1;
        output_line = malloc(needed_output_line_size);
        cur_output_line_size = needed_output_line_size;
        
        line_buffer = NULL;
        line_size = 0;
        output_line = NULL;
        max_string_size = INITIAL_MAX_STACK_LEN;
        while ((bytes_read = getline(&line_buffer, &line_size, stdin)) != -1) {
                /* Remove the newline */
                if (line_buffer[bytes_read - 1] == '\n') {
                        line_buffer[bytes_read - 1] = '\0';
                }
                
                retval = get_profile_event_func(line_buffer, &size, &func, &event);
                if (retval != 0) {
                        WARN("Unrecognized input line: '%s'\n", line_buffer);
                        continue;
                }
                
                /* Parse the line by calling the function pointer */
                if (event == PROFILE_EVENT_EUSTALL) {
                        retval = (*func)(line_buffer + size, &result);
                } else if (event == PROFILE_EVENT_STRING) {
                        string_size = 0;
                        retval = (*func)(line_buffer + size, &string_size);
                        
                        /* If we see a string that's longer than max_string_size,
                           we'll need to allocate more space, so increase needed_output_line_size */
                        if (max_string_size < string_size) {
                                max_string_size = string_size;
                                needed_output_line_size += (string_size - INITIAL_MAX_STACK_LEN);
                        }
                } else {
                        retval = (*func)(line_buffer + size, NULL);
                }
                
                if (retval) {
                        WARN("There was an error parsing a profile event: '%s'\n", line_buffer);
                        continue;
                } else if (event != PROFILE_EVENT_EUSTALL) {
                        continue;
                }
                
                /* Potentially `realloc` the output_line if we haven't got enough space */
                if (cur_output_line_size < needed_output_line_size) {
                        output_line = realloc(output_line, needed_output_line_size);
                        if (!output_line) {
                                ERR("Failed to allocate memory! Aborting.\n");
                        }
                        cur_output_line_size = needed_output_line_size;
                }
                
                /* Output the line into output_line */
                snprintf(output_line, cur_output_line_size, flame_fmt,
                         result.proc_name, result.pid, result.ustack_str,
                         result.kstack_str, result.gpu_file, result.gpu_symbol,
                         result.insn_text, result.stall_type_str, result.samp_offset);
        
                lookup = hash_table_get_val(flame_counts, output_line);
                if (lookup != NULL) {
                        *lookup += result.samp_count;
                } else {
                        hash_table_insert(flame_counts, output_line, result.samp_count);
                }
        }
        
        hash_table_traverse(flame_counts, tmp, lookup) {
                printf("%s %lu\n", tmp, *lookup);
        }
}
