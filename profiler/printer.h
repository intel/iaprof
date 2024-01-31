#pragma once

#include "bpf/gem_collector.h"
#include "stack_printer.h"

#define EVENT_LEN 12
#define TIME_LEN  12
#define CPU_LEN   4
#define PID_LEN   8
#define TID_LEN   8

int print_header() {
  printf("%-*.*s",  EVENT_LEN, EVENT_LEN, "EVENT");
  printf(" %-*.*s", TIME_LEN,  TIME_LEN,  "TIMESTAMP");
  printf(" %-*.*s", CPU_LEN,   CPU_LEN,   "CPU");
  printf(" %-*.*s", PID_LEN,   PID_LEN,   "PID");
  printf(" %-*.*s", TID_LEN,   TID_LEN,   "TID");
  printf(" %s\n",                         "ARGS");
  
  return 0;
}

int print_execbuf_start(struct execbuf_start_info *sinfo) {
  printf("%-*.*s",  EVENT_LEN, EVENT_LEN, "execbuf_start");
  printf(" %-*llu", TIME_LEN,             sinfo->time);
  printf(" %-*u",   CPU_LEN,              sinfo->cpu);
  printf(" %-*u",   PID_LEN,              sinfo->pid);
  printf(" %-*u",   TID_LEN,              sinfo->tid);
  print_stack(sinfo->pid, sinfo->stackid);
  
  return 0;
}
