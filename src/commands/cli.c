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

#include "commands/cli.h"
#include "visual/cli/cli.h"
#include "visual/cli/common.j.h"
#include "visual/cli/flamescope.j.h"
#include "visual/cli/flamegraph.j.h"
#include "utils/utils.h"

void flame_cli(int argc, char **argv)
{
  char *code[3];
  int len[3];
  char *names[3] = {
    "common.j",
    "flamegraph.j",
    0
  };
  
  code[0] = (char *)common_j;
  code[1] = (char *)flamegraph_j;
  code[2] = 0;
  
  len[0] = common_j_len;
  len[1] = flamegraph_j_len;
  len[2] = 0;
  
  render_visual(names, code, len, argc, argv);
}

void flamescope_cli(int argc, char **argv)
{
  char *code[3];
  int len[3];
  char *names[3] = {
    "common.j",
    "flamescope.j",
    0
  };
  
  code[0] = (char *)common_j;
  code[1] = (char *)flamescope_j;
  code[2] = 0;
  
  len[0] = common_j_len;
  len[1] = flamescope_j_len;
  len[2] = 0;
  
  render_visual(names, code, len, argc, argv);
}
