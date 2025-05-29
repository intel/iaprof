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

/*
  PVC Profile
  =================
*/

#include <string.h>
#include "iaprof.h"
#include "printers/debug/debug_printer.h"
#include "commands/record.h"
#include "commands/flame.h"
#include "commands/flame_cli.h"
#include "commands/flamescope.h"

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "?"
#endif

enum commands {
  RECORD = 0,
  FLAME = 1,
  FLAME_CLI = 2,
  FLAMESCOPE = 3,
  COMMANDS_MAX
};
static char *command_strs[] = {
  [RECORD] = "record",
  [FLAME] = "flame",
  [FLAME_CLI] = "flame-cli",
  [FLAMESCOPE] = "flamescope",
};
static void (*command_ptrs[]) (int, char**) = {
  [RECORD] = &record,
  [FLAME] = &flame,
  [FLAME_CLI] = &flame_cli,
  [FLAMESCOPE] = &flamescope,
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
                  command_ptrs[i](argc-1, argv+1);
                  return 0;
          }
  }

  ERR("Command '%s' not recognized! Aborting.\n", argv[1]);
  return 1;
}
