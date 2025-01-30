/*
  PVC Profile
  =================
*/

#include "iaprof.h"
#include "commands/record.h"

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "?"
#endif

int main(int argc, char **argv)
{
  /* Determine the subcommand */
  record(argc, argv);
}
