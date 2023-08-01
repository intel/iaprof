/*
  i915 TEST
  =================
  
  This is a small test program to play around with the i915 performance counter interface.
*/

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

#include "drm_helper.h"
#include "i915_helper.h"
#include "eustall_helper.h"

/*******************
* COMMANDLINE ARGS *
*******************/

static struct option long_options[] = {
};

int read_opts(int argc, char **argv) {
  int option_index;
  char c;
  
  while(1) {
    option_index = 0;
    c = getopt_long(argc, argv, "s:", long_options, &option_index);
    if(c == -1) {
      break;
    }
    switch(c) {
      case 0:
        printf("option %s\n", long_options[option_index].name);
        break;
    }
  }
}

/*******************
*     COLLECT      *
*******************/

int perf_fd;
pthread_t workload_thread_id;
static int interval_num = 0;
static int interval_length = 1;
static int interval_signal;
timer_t interval_timer;
static char stopping = 0;

/* This is what happens on a single profiling interval */
void workload_thread_interval(int s) {
}

int init_interval_signal() {
  struct sigevent sev, runtime_sev;
  struct itimerspec its, runtime_its;
  struct sigaction sa;
  sigset_t interval_mask, runtime_mask;
  pid_t tid;

  interval_signal = SIGRTMIN;

  /* Set up a signal handler for the master.
     The call to sigaddset here blocks the stop signal until an interval is completed. */
  sa.sa_flags = 0;
  sa.sa_handler = workload_thread_interval;
  sigemptyset(&sa.sa_mask);
  if(sigaction(interval_signal, &sa, NULL) == -1) {
    fprintf(stderr, "Error creating interval signal handler. Aborting.\n");
    exit(1);
  }

  /* Block the interval signal */
  sigemptyset(&interval_mask);
  sigaddset(&interval_mask, interval_signal);
  if(sigprocmask(SIG_SETMASK, &interval_mask, NULL) == -1) {
    fprintf(stderr, "Error blocking signal. Aborting.\n");
    exit(1);
  }

  /* Create the interval timer */
  tid = syscall(SYS_gettid);
  sev.sigev_notify = SIGEV_THREAD_ID;
  sev.sigev_signo = interval_signal;
  sev.sigev_value.sival_ptr = &interval_timer;
  sev._sigev_un._tid = tid;
  if(timer_create(CLOCK_REALTIME, &sev, &interval_timer) == -1) {
    fprintf(stderr, "Error creating timer. Aborting.\n");
    exit(1);
  }

  /* Set the interval timer */
  its.it_value.tv_sec     = interval_length / 1000;
  its.it_value.tv_nsec    = (interval_length % 1000) * 1000000;
  its.it_interval.tv_sec  = its.it_value.tv_sec;
  its.it_interval.tv_nsec = its.it_value.tv_nsec;
  if(timer_settime(interval_timer, 0, &its, NULL) == -1) {
    fprintf(stderr, "Error setting the timer. Aborting.\n");
    exit(1);
  }
  
  /* Unblock the interval signal */
  if(sigprocmask(SIG_UNBLOCK, &interval_mask, NULL) == -1) {
    fprintf(stderr, "Error unblocking signal. Aborting.\n");
    exit(1);
  }

  return 0;
}

void workload_thread_stop(int s) {
  timer_delete(interval_timer);
  stopping = 1;
}

void *workload_thread_main(void *a) {
  int ch, sig;
  sigset_t mask;
  
  /* Run a GPGPU FILL workload */
  

  /* Wait on SIGTERM */
/*   sigemptyset(&mask); */
/*   sigaddset(&mask, SIGTERM); */
/*   if(sigprocmask(SIG_BLOCK, &mask, NULL) == -1) { */
/*     fprintf(stderr, "Error blocking SIGTERM. Aborting.\n"); */
/*     exit(1); */
/*   } */
/*   while(sigwait(&mask, &sig) == 0) { */
/*     if(sig == SIGTERM) { */
/*       break; */
/*     } */
/*   } */
  
  /* Make sure we get at least one interval; if
      no intervals have run yet, send the interval signal
      manually */
/*   if(interval_num == 0) { */
/*     pthread_kill(workload_thread_id, interval_signal); */
/*   } */
  
/*   workload_thread_stop(SIGTERM); */
  return NULL;
}

int start_workload_thread() {
  int retval;
  sigset_t mask;

  /* The main thread should block SIGTERM, so that all
     SIGTERMs go to the UI thread. */
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  if(sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
    fprintf(stderr, "Error blocking signal. Aborting.\n");
    return -1;
  }

  retval = pthread_create(&workload_thread_id, NULL, &workload_thread_main, NULL);
  if(retval != 0) {
    fprintf(stderr, "Failed to call pthread_create. Something is very wrong. Aborting.\n");
    return -1;
  }

  return 0;
}

/*******************
*       MAIN       *
*******************/

int main(int argc, char **argv) {
  device_info *devinfo;
  int ret;
  uint8_t *perf_buf;
  
  /* Grab the i915 driver file descriptor */
  devinfo = open_first_driver();
  if(!devinfo) {
    fprintf(stderr, "Failed to open any drivers. Aborting.\n");
    exit(1);
  }
  
  /* Get information about the device */
  if(get_drm_device_info(devinfo) != 0) {
    fprintf(stderr, "Failed to get device info. Aborting.\n");
    exit(1);
  }
  
  if(i915_query_engines(devinfo->fd, &(devinfo->engine_info)) != 0) {
    fprintf(stderr, "Failed to get engine info. Aborting.\n");
    exit(1);
  }
  
  printf("Device ID: 0x%X\n", devinfo->id);
  
  /* Configure the i915 performance counter file descriptor */
  perf_fd = configure_eustall(devinfo);
  
  /* Begin collecting results */
  if(start_workload_thread() != 0) {
    fprintf(stderr, "Failed to start the collection thread. Aborting.\n");
    exit(1);
  }
  
  /* Poll for updates to the buffer */
  perf_buf = malloc(p_user);
  while(stopping == 0) {
    struct pollfd pollfd = {
      .fd = perf_fd,
      .events = POLLIN
    };
    ret = poll(&pollfd, 1, 1000);
    if(ret == 0) {
      continue;
    } else if(ret < 0) {
      fprintf(stderr, "An error occurred while reading the file descriptor. Aborting.\n");
      exit(1);
    }
    
    /* There's things to read */
    ret = read(perf_fd, perf_buf, p_user);
    if(ret > 0) {
      handle_eustall_samples(perf_buf, ret);
    }
  }
  printf("Finished\n");
  
  pthread_kill(workload_thread_id, SIGTERM);
  pthread_join(workload_thread_id, NULL);
  
  free_driver(devinfo);
}
