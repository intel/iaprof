/*
  i915 TEST
  =================
  
  This is a small test program to play around with the i915 performance counter interface.
*/

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <getopt.h>
#include <poll.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <pthread.h>
#include <assert.h>

#include "pvc_profile.h"

#include "common.h"
#include "drm_helper.h"
#include "i915_helper.h"
#include "eustall_collector.h"

#include "bpf/gem_collector.h"
#include "bpf/gem_collector.skel.h"
#include "gem_collector.h"

#include "printer.h"

/*******************
* COMMANDLINE ARGS *
*******************/

int pid = 0;
char bpf = 0;
char verbose = 0;
char debug = 0;

static struct option long_options[] = {
  {"pid", required_argument, 0, 'p'},
  {"bpf", no_argument, 0, 'b'},
  {"verbose", no_argument, 0, 'v'},
  {"debug", no_argument, 0, 'd'},
  {0}
};

int read_opts(int argc, char **argv) {
  int option_index;
  char c;
  
  while(1) {
    option_index = 0;
    c = getopt_long(argc, argv, "p:bvd", long_options, &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
      case 'd':
        debug = 1;
        break;
      case 'p':
        pid = (int) strtol(optarg, NULL, 10);
        break;
      case 'b':
        bpf = 1;
        break;
      case 'v':
        verbose = 1;
        break;
      case 0:
        printf("option %s\n", long_options[option_index].name);
        break;
    }
  }
  
  return 0;
}

void sanity_checks() {
  static_assert(sizeof(struct buffer_info) != sizeof(struct binary_info),
                "buffer_info is the same size as binary_info");
  static_assert(sizeof(struct buffer_info) != sizeof(struct execbuf_start_info),
                "buffer_info is the same size as execbuf_start_info");
  static_assert(sizeof(struct buffer_info) != sizeof(struct execbuf_end_info),
                "buffer_info is the same size as execbuf_end_info");
                
  static_assert(sizeof(struct binary_info) != sizeof(struct execbuf_start_info),
                "binary_info is the same size as execbuf_start_info");
  static_assert(sizeof(struct binary_info) != sizeof(struct execbuf_end_info),
                "binary_info is the same size as execbuf_end_info");
                
  static_assert(sizeof(struct execbuf_start_info) != sizeof(struct execbuf_end_info),
                "execbuf_start_info is the same size as execbuf_end_info");
}

/*******************
*     COLLECT      *
*******************/

/* Global array of GEMs that we've seen.
   This is what we'll search through when we get an
   EU stall sample. */
pthread_rwlock_t gem_lock = PTHREAD_RWLOCK_INITIALIZER;
GEM_ARR_TYPE *gem_arr = NULL;
size_t gem_arr_sz = 0, gem_arr_used = 0;

struct bpf_info_t bpf_info = {};
int perf_fd;
pthread_t collect_thread_id;
static int interval_num = 0;
static int interval_length = 1;
static int interval_signal;
timer_t interval_timer;
static char collect_thread_should_stop = 0;
static char main_thread_should_stop = 0;

void stop_collect_thread() {
  collect_thread_should_stop = 1;
}

void *collect_thread_main(void *a) {
  uint8_t *perf_buf;
  int perf_fd;
  int retval;
  sigset_t mask;
  
  /* The collect thread should block SIGINT, so that all
     SIGINTs go to the main thread. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  if(sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
    fprintf(stderr, "Error blocking signal. Aborting.\n");
    return NULL;
  }
  
  /* Initialize the BPF program */
  init_bpf_prog();
  
  /* Initialize the EU stall collection */
  perf_fd = configure_eustall();
  perf_buf = malloc(p_user);
  struct pollfd pollfd = {
    .fd = perf_fd,
    .events = POLLIN,
  };
  
  while(collect_thread_should_stop == 0) {
    /* Quickly check if there are EU stall samples */
    retval = poll(&pollfd, 1, 1);
    if(retval < 0) {
      fprintf(stderr, "An error occurred while readin the EU stall file descriptor! Aborting.\n");
      goto cleanup;
    } else if(retval > 0) {
      /* There are samples to read */
      retval = read(perf_fd, perf_buf, p_user);
      if(retval > 0) {
        handle_eustall_samples(perf_buf, retval);
      }
    }
    /* If retval == 0, fall through */
    
    /* Sit for a bit on the GEM info ringbuffer */
    ring_buffer__poll(bpf_info.rb, 100);
    
    if(debug) {
      print_ringbuf_stats();
    }
  }
  
cleanup:
  free(perf_buf);
  close(perf_fd);
  deinit_bpf_prog();
  
  return NULL;
}

int start_collect_thread() {
  int retval;

  retval = pthread_create(&collect_thread_id, NULL, &collect_thread_main, NULL);
  if(retval != 0) {
    fprintf(stderr, "Failed to call pthread_create. Something is very wrong. Aborting.\n");
    return -1;
  }

  return 0;
}

/*******************
*       MAIN       *
*******************/

void stop_main_thread(int sig) {
  main_thread_should_stop = 1;
}

int main(int argc, char **argv) {
  struct sigaction sa;
  struct timespec leftover, request = {
    1, 0
  };
  GEM_ARR_TYPE *gem;
  int i;
  uint64_t n;
  struct offset_profile **found;
  
  sanity_checks();
  read_opts(argc, argv);
  
  /* Begin collecting results */
  if(start_collect_thread() != 0) {
    fprintf(stderr, "Failed to start the collection thread. Aborting.\n");
    exit(1);
  }
  
  sa.sa_flags = 0;
  sa.sa_handler = stop_main_thread;
  sigemptyset(&sa.sa_mask);
  if(sigaction(SIGINT, &sa, NULL) == -1) {
    fprintf(stderr, "Error creating interval signal handler. Aborting.\n");
    exit(1);
  }
  
  /* This loop runs until the profiler gets a signal to stop. 
     It prints out per-interval stats, then sleeps until the next
     interval. */
  print_header();
  while(!main_thread_should_stop) {
    #if 0
    if(pthread_rwlock_rdlock(&gem_lock) != 0) {
      fprintf(stderr, "Failed to grab the gem_lock for reading.\n");
      continue;
    }
    
    for(i = 0; i < gem_arr_used; i++) {
      gem = &gem_arr[i];
      if(!gem->is_shader) continue;
      printf("  handle: %u\n", gem->kinfo.handle);
      hash_table_traverse(gem->shader_profile.counts, n, found) {
        printf("    offset: 0x%lx\n", n);
        if((*found)->active) printf("      active: %u\n", (*found)->active);
        if((*found)->other) printf("      other: %u\n", (*found)->other);
        if((*found)->control) printf("      control: %u\n", (*found)->control);
        if((*found)->pipestall) printf("      pipestall: %u\n", (*found)->pipestall);
        if((*found)->send) printf("      send: %u\n", (*found)->send);
        if((*found)->dist_acc) printf("      dist_acc: %u\n", (*found)->dist_acc);
        if((*found)->sbid) printf("      sbid: %u\n", (*found)->sbid);
        if((*found)->sync) printf("      sync: %u\n", (*found)->sync);
        if((*found)->inst_fetch) printf("      inst_fetch: %u\n", (*found)->inst_fetch);
      }
    }
    
    if(pthread_rwlock_unlock(&gem_lock) != 0) {
      fprintf(stderr, "Failed to unlock the gem_lock.\n");
      continue;
    }
    #endif
    nanosleep(&request, &leftover);
  }
  
  /* Wait for the collection thread to finish */
  stop_collect_thread();
  pthread_join(collect_thread_id, NULL);
}
