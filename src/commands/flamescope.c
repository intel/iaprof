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

#include "commands/flamescope.h"
#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"
#include "utils/hash_table.h"
#include "utils/utils.h"

/* The format for the full stack on a line of flame graph output. */
static const char *samp_fmt =
        "%s %u [000] %.6lf: %lu stalls:\n";
static const char *frame_fmt        = "        00000000 %s%s ()\n";
static const char *frame_offset_fmt = "        00000000 0x%lx%s ()\n";
#define INITIAL_MAX_STACK_LEN 4096

static FILE *input_file = NULL;

void print_flamescope_sample(struct eustall_result *eresult, struct interval_result *iresult)
{
        int last_changed;
        char *stack_str, *cursor;
        size_t size;

        printf(samp_fmt, get_string(eresult->proc_name_id),
                eresult->pid, iresult->time, eresult->samp_count);
        
        printf(frame_offset_fmt, eresult->samp_offset, "_[g]");
        printf(frame_fmt, get_string(eresult->stall_type_id), "_[g]");
        printf(frame_fmt, get_string(eresult->gpu_symbol_id), "_[G]");
        printf(frame_fmt, "-", "");
        if (eresult->ustack_id) {
                stack_str = get_string(eresult->ustack_id);
                size = strlen(stack_str);
                cursor = stack_str + size;
                last_changed = -1;
                while (cursor != stack_str) {
                        if (*cursor == ';') {
                                if (cursor < stack_str + size - 1) {
                                        printf(frame_fmt, cursor + 1, "");
                                }
                                if (last_changed != -1) { stack_str[last_changed] = ';'; }
                                last_changed = cursor - stack_str;
                                *cursor = 0;
                        }
                        cursor -= 1;
                }
                if (cursor < stack_str + size - 1) {
                        printf(frame_fmt, cursor, "");
                }
                if (last_changed != -1) { stack_str[last_changed] = ';'; }
        }
        printf("\n");
}

void flamescope(int argc, char **argv)
{
        ssize_t bytes_read;
        size_t line_size, size;
        enum profile_event event;
        char *line_buffer;
        int (*func)(char *, void *);
        int retval;
        struct eustall_result eresult;
        struct interval_result iresult;

        input_file = stdin;
        line_buffer = NULL;
        line_size = 0;
        while ((bytes_read = getline(&line_buffer, &line_size, input_file)) !=
               -1) {
                /* Remove the newline */
                if (line_buffer[bytes_read - 1] == '\n') {
                        line_buffer[bytes_read - 1] = '\0';
                }

                retval = get_profile_event_func(line_buffer, &size, &func,
                                                &event);
                if (retval != 0) {
                        WARN("Unrecognized input line: '%s'\n",
                                line_buffer);
                        continue;
                }

                /* Parse the line by calling the function pointer */
                if (event == PROFILE_EVENT_EUSTALL) {
                        retval = (*func)(line_buffer + size, &eresult);
                } else if (event == PROFILE_EVENT_INTERVAL_START) {
                        retval = (*func)(line_buffer + size, &iresult);
                } else {
                        retval = (*func)(line_buffer + size, NULL);
                }

                if (retval) {
                        WARN("There was an error parsing a profile event: '%s'\n",
                                line_buffer);
                        continue;
                } else if (event != PROFILE_EVENT_EUSTALL) {
                        continue;
                }
                
                if (event == PROFILE_EVENT_EUSTALL) {
                        print_flamescope_sample(&eresult, &iresult);
                }
        }

        if (line_buffer != NULL) {
                free(line_buffer);
        }
}
