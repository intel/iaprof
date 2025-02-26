/*
  PVC Profile
  =================
*/

#include <string.h>
#include "iaprof.h"
#include "printers/debug/debug_printer.h"
#include "commands/record.h"
#include "commands/flame.h"

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "?"
#endif

enum commands {
  RECORD = 0,
  FLAME = 1,
  COMMANDS_MAX
};
static char *command_strs[] = {
  [RECORD] = "record",
  [FLAME] = "flame",
};
static void (*command_ptrs[]) (int, char**) = {
  [RECORD] = &record,
  [FLAME] = &flame,
};

int main(int argc, char **argv)
{
  int i;
  
  if (argc < 2) {
          ERR("No commands specified. Aborting.\n");
  }
  
  /* Determine the subcommand */
  for (i = 0; i < COMMANDS_MAX; i++) {
          if (strcmp(argv[1], command_strs[i]) == 0) {
                  command_ptrs[i](argc, argv);
                  return 0;
          }
  }
  
  ERR("Command not recognized! Aborting.\n");
  return 1;
}
