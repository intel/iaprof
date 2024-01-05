#pragma once

#include <dlfcn.h>
#include <iga.h>

iga_context_t *iga_init() {
  iga_context_options_t opts = {
    cb = sizeof(iga_context_options_t),
    gen = IGA_XE_HPC
  };
}

/* void *get_iga() { */
/*   void *retval; */
/*    */
/*   retval = dlopen("libiga64.so", RTLD_NOW); */
/*   if(!retval) { */
/*     fprintf(stderr, "Failed to open libiga64.so: %s\n", dlerror()); */
/*     exit(1); */
/*   } */
/*   return retval; */
/* } */

/* void *get_disasm() { */
/*    */
/* } */
