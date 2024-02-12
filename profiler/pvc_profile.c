/*
  PVC Profile
  =================
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

#include <iga/iga.h>

#include "pvc_profile.h"

#include "common.h"
#include "utils/utils.h"
#include "drm_helper.h"

#include "eustall_collector.h"
#include "shader_decoder.h"
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
  static_assert(sizeof(struct mapping_info) != sizeof(struct binary_info),
                "mapping_info is the same size as binary_info");
  static_assert(sizeof(struct mapping_info) != sizeof(struct vm_bind_info),
                "mapping_info is the same size as vm_bind_info");
  static_assert(sizeof(struct mapping_info) != sizeof(struct vm_unbind_info),
                "mapping_info is the same size as vm_unbind_info");
  static_assert(sizeof(struct mapping_info) != sizeof(struct execbuf_start_info),
                "mapping_info is the same size as execbuf_start_info");
  static_assert(sizeof(struct mapping_info) != sizeof(struct execbuf_end_info),
                "mapping_info is the same size as execbuf_end_info");
                
  static_assert(sizeof(struct binary_info) != sizeof(struct vm_bind_info),
                "binary_info is the same size as vm_bind_info");
  static_assert(sizeof(struct binary_info) != sizeof(struct vm_unbind_info),
                "binary_info is the same size as vm_unbind_info");
  static_assert(sizeof(struct binary_info) != sizeof(struct execbuf_start_info),
                "binary_info is the same size as execbuf_start_info");
  static_assert(sizeof(struct binary_info) != sizeof(struct execbuf_end_info),
                "binary_info is the same size as execbuf_end_info");
                
  static_assert(sizeof(struct vm_bind_info) != sizeof(struct vm_unbind_info),
                "vm_bind_info is the same size as vm_unbind_info");
  static_assert(sizeof(struct vm_bind_info) != sizeof(struct execbuf_start_info),
                "vm_bind_info is the same size as execbuf_start_info");
  static_assert(sizeof(struct vm_bind_info) != sizeof(struct execbuf_end_info),
                "vm_bind_info is the same size as execbuf_end_info");
                
  static_assert(sizeof(struct vm_unbind_info) != sizeof(struct execbuf_start_info),
                "vm_unbind_info is the same size as execbuf_start_info");
  static_assert(sizeof(struct vm_unbind_info) != sizeof(struct execbuf_end_info),
                "vm_unbind_info is the same size as execbuf_end_info");
                
  static_assert(sizeof(struct execbuf_start_info) != sizeof(struct execbuf_end_info),
                "execbuf_start_info is the same size as execbuf_end_info");
}

/*******************
*     COLLECT      *
*******************/

/* Global array of GEMs that we've seen.
   This is what we'll search through when we get an
   EU stall sample. */
pthread_rwlock_t buffer_profile_lock = PTHREAD_RWLOCK_INITIALIZER;
struct buffer_profile *buffer_profile_arr = NULL;
size_t buffer_profile_size = 0, buffer_profile_used = 0;

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
  int perf_fd, i;
  int retval, retry_eustalls, len;
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
  if(perf_fd < 0) {
    fprintf(stderr, "Failed to configure EU stalls. Aborting!\n");
    exit(1);
  }
  perf_buf = malloc(p_user);
  struct pollfd pollfd = {
    .events = POLLIN,
  };
  
  retry_eustalls = 0;
  while(collect_thread_should_stop == 0) {
    
    /* Check if there are eustalls */
    retry_eustalls = 0;
    pollfd.fd = perf_fd;
    retval = poll(&pollfd, 1, 1);
    if(retval < 0) {
      fprintf(stderr, "An error occurred while readin the EU stall file descriptor! Aborting.\n");
      goto cleanup;
    } else if(retval > 0) {
      /* There are samples to read */
      len = read(perf_fd, perf_buf, p_user);
      if(len > 0) {
        retry_eustalls = handle_eustall_samples(perf_buf, len);
        if(retry_eustalls == -1) {
          return NULL;
        } else if(retry_eustalls >= 1) {
          fprintf(stderr, "WARNING: Dropping %d eustalls on the floor.\n", retry_eustalls);
        }
      }
      /* If retval == 0, fall through */
    }
    
    /* Sit for a bit on the GEM info ringbuffer */
    ring_buffer__poll(bpf_info.rb, 100);
  }
  
  /* Once we've been told to clean up, check one last time */
  ring_buffer__poll(bpf_info.rb, 100);
  
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
  struct buffer_profile *gem;
  int i, n;
  struct offset_profile **found;
  iga_context_t *ctx;
  uint64_t tmp_offset, *tmp;
  char *insn_text;
  char *failed_decode = "[failed_decode]";
  
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
  if(debug) {
    print_header();
  }
  while(!main_thread_should_stop) {
    nanosleep(&request, &leftover);
  }
  
  /* Wait for the collection thread to finish */
  stop_collect_thread();
  pthread_join(collect_thread_id, NULL);
  fflush(stdout);
  
  /* Print out the final results */
  #define PRINT_FRONT_STACK() \
    printf("%s;", gem->exec_info.name); \
    printf("%u;", gem->exec_info.pid); \
    if(gem->execbuf_stack_str) { \
      printf("%s", gem->execbuf_stack_str); \
    } else { \
      printf("[unknown];"); \
    } \
    printf("-;"); \
    printf("%s_[g];", insn_text);
  
  ctx = iga_init();
  for(i = 0; i < buffer_profile_used; i++) {
    gem = &buffer_profile_arr[i];
    if(!gem->has_stalls) continue;
    if(gem->exec_info.pid == 0) {
      fprintf(stderr, "WARNING: PID for handle %u is zero!\n", gem->mapping_info.handle);
    }
    hash_table_traverse(gem->shader_profile.counts, tmp_offset, tmp) {
      found = (struct offset_profile **) tmp;
      
      /* First, disassemble the instruction */
      if((!gem->buff_sz) || (!gem->buff)) {
        fprintf(stderr, "WARNING: Got an EU stall on a buffer we haven't copied yet. handle=%u\n", gem->vm_bind_info.handle);
        continue;
      }
      if(gem->mapping_info.handle == 2) {
        dump_buffer(gem->buff, gem->buff_sz, gem->mapping_info.handle);
      }
      if(tmp_offset > gem->buff_sz) {
        fprintf(stderr, "WARNING: Got an EU stall past the end of a buffer. ");
        fprintf(stderr, "handle=%u cpu_addr=%p offset=0x%lx buff_sz=%lu\n",
                gem->mapping_info.handle, gem->buff, tmp_offset, gem->buff_sz);
        insn_text = failed_decode;
      } else {
        insn_text = iga_disassemble_single(ctx, gem->buff + tmp_offset);
        if(insn_text == NULL) {
          insn_text = failed_decode;
          fprintf(stderr, "Failed disassembly happened at handle=%u offset=0x%lx\n",
                  gem->mapping_info.handle, tmp_offset);
        }
        for(n = 0; n < strlen(insn_text); n++) {
          if(insn_text[n] == ';') {
            insn_text[n] = ',';
          }
        }
      }
      
      if((*found)->active) {
        PRINT_FRONT_STACK();
        printf("active_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->active);
      }
      if((*found)->other) {
        PRINT_FRONT_STACK();
        printf("other_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->other);
      }
      if((*found)->control) {
        PRINT_FRONT_STACK();
        printf("control_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->control);
      }
      if((*found)->pipestall) {
        PRINT_FRONT_STACK();
        printf("pipestall_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->pipestall);
      }
      if((*found)->send) {
        PRINT_FRONT_STACK();
        printf("send_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->send);
      }
      if((*found)->dist_acc) {
        PRINT_FRONT_STACK();
        printf("dist_acc_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->dist_acc);
      }
      if((*found)->sbid) {
        PRINT_FRONT_STACK();
        printf("sbid_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->sbid);
      }
      if((*found)->sync) {
        PRINT_FRONT_STACK();
        printf("sync_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->sync);
      }
      if((*found)->inst_fetch) {
        PRINT_FRONT_STACK();
        printf("inst_fetch_[g];");
        printf("0x%lx_[g] %u\n", tmp_offset, (*found)->inst_fetch);
      }
    }
  }
}
