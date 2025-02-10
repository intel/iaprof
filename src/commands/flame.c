#include "commands/flame.h"
#include "printers/interval/interval_printer.h"
#include "printers/debug/debug_printer.h"

void flame(int argc, char **argv)
{
        ssize_t bytes_read;
        size_t line_size, size;
        char *line_buffer;
        void (*func) (char *);
        
        line_buffer = NULL;
        line_size = 0;
        while ((bytes_read = getline(&line_buffer, &line_size, stdin)) != -1) {
                /* Remove the newline */
                if (line_buffer[bytes_read - 1] == '\n') {
                        line_buffer[bytes_read - 1] = '\0';
                }
                
                func = get_profile_line_func(line_buffer, &size);
                if (!func) {
                        WARN("Unrecognized input line: '%s'\n", line_buffer);
                        break;
                }
                
                (*func)(line_buffer + size);
        }
}
