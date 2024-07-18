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
#include <sys/epoll.h>
#include <time.h>
#include <string.h>
#include <inttypes.h>
#include <sys/wait.h>
#include <pthread.h>
#include <assert.h>
#include <sys/time.h>

#include "iaprof.h"

/* Helpers */
#include "drm_helpers/drm_helpers.h"
#include "i915_helpers/i915_helpers.h"

/* Collectors */
#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/bpf_i915/bpf/gem_collector.h"
#include "collectors/bpf_i915/bpf/gem_collector.skel.h"
#include "collectors/debug_i915/debug_i915_collector.h"

/* Printers */
#include "printers/printer.h"
#include "printers/flamegraph/flamegraph_printer.h"
#include "printers/debug/debug_printer.h"

#include "gpu_parsers/shader_decoder.h"

/*******************
* COMMANDLINE ARGS *
*******************/

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "?"
#endif
int pid = 0;
char verbose = 0;
char debug = 0;
char bb_debug = 0;
char quiet = 0;
char *g_sidecar = NULL;
int g_samples_matched = 0;
int g_samples_unmatched = 0;

static struct option long_options[] = {
	{ "debug", no_argument, 0, 'd' }, { "help", no_argument, 0, 'h' },
	{ "quiet", no_argument, 0, 'q' }, { "verbose", no_argument, 0, 'v' },
        { "batchbuffer-debug", no_argument, 0, 'b'},
	{ "version", no_argument, 0, 0 }, { 0 }
};

void usage()
{
	printf("USAGE: iaprof [-dhqv] [command]\n\n");
	printf(" e.g.:\n");
	printf("        iaprof > profile.txt            # profile until Ctrl-C.\n");
	printf("        iaprof sleep 30 > profile.txt   # profile for 30 seconds.\n");
	printf("\noptional arguments:\n");
	printf("        -d, --debug              debug\n");
	printf("        -b, --batchbuffer-debug  debug the parsing of batchbuffers\n");
	printf("        -h, --help               help\n");
	printf("        -q, --quiet              quiet\n");
	printf("        -v, --verbose            verbose\n");
	printf("        command                  profile system-wide while command runs\n\n");
	printf("Version: %s\n", GIT_COMMIT_HASH);
}

void check_permissions()
{
	if (geteuid() != 0) {
		printf("Tool currently needs superuser (root) permission. "
		       "Please consider running with sudo. Exiting.\n");
		exit(1);
	}
}

int read_opts(int argc, char **argv)
{
	int option_index, size = 0;
	char c;

	while (1) {
		option_index = 0;
		c = getopt_long(argc, argv, "dbhqv", long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'd':
			debug = 1;
			break;
		case 'b':
			bb_debug = 1;
			break;
		case 'h':
			usage();
			exit(0);
			/* no fallthrough */
		case 'q':
			quiet = 1;
			break;
		case 'v':
			verbose = 1;
			break;
		case 0:
			if (strcmp(long_options[option_index].name,
				   "version") == 0) {
				printf("Version: %s\n", GIT_COMMIT_HASH);
				exit(0);
			} else {
				printf("option %s\n",
				       long_options[option_index].name);
			}
			break;
		}
	}

	if (optind < argc) {
		for (int i = optind; i < argc; i++) {
			size += strlen(argv[i]) + 1;
		}
		if (!(g_sidecar = malloc(size))) {
			fprintf(stderr, "ERROR: out of memory.\n");
			exit(2);
		}
		for (int i = optind, size = 0; i < argc; i++) {
			size += sprintf(g_sidecar + size, "%s ", argv[i]);
		}
		g_sidecar[--size] = '\0';
	}

	return 0;
}

void print_status(const char *msg)
{
	if (!quiet) {
		fprintf(stderr, "%s", msg);
	}
}

/*******************
*     COLLECT      *
*******************/

/**
  Global array of GEMs that we've seen.
  This is what we'll search through when we get an
  EU stall sample.
**/
pthread_rwlock_t buffer_profile_lock = PTHREAD_RWLOCK_INITIALIZER;
struct buffer_profile *buffer_profile_arr = NULL;
size_t buffer_profile_size = 0, buffer_profile_used = 0;
uint64_t iba = 0;

/* Collector info */
struct device_info devinfo = {};
struct bpf_info_t bpf_info = {};
struct eustall_info_t eustall_info = {};
struct debug_i915_info_t debug_i915_info = {};
#define MAX_EPOLL_EVENTS 64

/* Thread and interval */
pthread_t collect_thread_id;
pthread_t sidecar_thread_id;
static int interval_num = 0;
static int interval_length = 1;
static int interval_signal;
timer_t interval_timer;
static char collect_thread_should_stop = 0;
static char collect_thread_profiling = 0;
static char main_thread_should_stop = 0;

void stop_collect_thread()
{
	collect_thread_should_stop = 1;
}

void add_to_epoll_fd(int fd)
{
        struct epoll_event e = {};
        
        printf("Adding fd %d to the epoll_fd\n", fd);
        e.events = EPOLLIN;
        e.data.fd = fd;
        if (epoll_ctl(bpf_info.epoll_fd, EPOLL_CTL_ADD, fd, &e) < 0) {
                fprintf(stderr, "Failed to add to the ringbuffer's epoll instance. Aborting.\n");
                exit(1);
        }
}

void init_collect_thread()
{
	sigset_t mask;
        int retval;
        
	/* The collect thread should block SIGINT, so that all
           SIGINTs go to the main thread. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		fprintf(stderr, "Error blocking signal. Aborting.\n");
		return;
	}

        /* We'll need the i915 driver for multiple collectors */
	retval = open_first_driver(&devinfo);
	if (retval != 0) {
		fprintf(stderr, "Failed to open any drivers. Aborting.\n");
		exit(1);
	}

	/* Get information about the device */
	if (get_drm_device_info(&devinfo) != 0) {
		fprintf(stderr, "Failed to get device info. Aborting.\n");
		exit(1);
	}

	if (i915_query_engines(devinfo.fd, &(devinfo.engine_info)) != 0) {
		fprintf(stderr, "Failed to get engine info. Aborting.\n");
		exit(1);
	}


        /* BPF collector */
        init_bpf_i915();
        
        /* EU stall collector. Add to the epoll_fd that the bpf_i915
           collector created. */
        if (init_eustall(&devinfo)) {
		fprintf(stderr, "Failed to configure EU stalls. Aborting!\n");
		exit(1);
	}
}

int handle_fd_read(struct epoll_event *event)
{
        int len, retval;
        enum eustall_status status;
        
        if ((event->events & EPOLLERR) ||
            (event->events & EPOLLHUP)) {
                /* Error or hangup. Abort! */
                fprintf(stderr, "Encountered an error in one");
                fprintf(stderr, "of the file descriptors. Aborting.\n");
                return -1;
        }
        if (!(event->events & EPOLLIN)) {
                /* The fd is not ready to be read, so skip it */
                fprintf(stderr, "WARNING: EPOLLIN was not set. Why were we awoken?\n");
                return 0;
        }
        printf("Got EPOLLIN on fd %d.\n", event->data.fd);
        if (event->data.fd == eustall_info.perf_fd) {
                /* eustall collector */
                printf("Got an eustall sample!\n");
        		len = read(event->data.fd, eustall_info.perf_buf, DEFAULT_USER_BUF_SIZE);
        		if (len > 0) {
        			status = handle_eustall_samples(eustall_info.perf_buf, len);
                                if (status != EUSTALL_STATUS_OK) {
                                        fprintf(stderr,
                                               "WARNING: Got an error handling eustall samples!\n");
                                }
                        }
        } else if (event->data.fd == 0) {
                /* bpf_i915 collector. Note that libbpf sets event->data.fd to
                   ring_cnt, which, because we only have one ringbuffer, is zero. */
                printf("Got a BPF sample!\n");
                retval = ring_buffer__consume(bpf_info.rb);
                if (retval < 0) {
                        printf("ring_buffer__consume failed. Aborting.\n");
                        exit(1);
                } else {
                        printf("Ring buffer processed %d records.\n", retval);
                }
        } else {
                /* debug_i915 collector */
                printf("Got a debug sample on fd %d!\n", event->data.fd);
                read_debug_i915_events(event->data.fd);
        }
        
        return 0;
}

void *collect_thread_main(void *a)
{
	int i, startsecs, nfds;
	struct timeval tv;
        struct epoll_event *events;
        
        init_collect_thread();
        
        events = calloc(MAX_EPOLL_EVENTS, sizeof(struct epoll_event));

	if (collect_thread_should_stop == 0)
		print_status("Profiling... Ctrl-C to end.\n");

	if (verbose)
		print_header();

	gettimeofday(&tv, NULL);
	startsecs = (int)tv.tv_sec;

	collect_thread_profiling = 1;
	while (collect_thread_should_stop == 0) {
		gettimeofday(&tv, NULL);

                /* Print the status line */
                fprintf(stderr, "\r");
                if (!isatty(STDERR_FILENO)) {
                        fprintf(stderr, "\n");
                }
		fprintf(stderr,
			"Status: profiling for %d secs, %d samples matched, %d samples unmatched. ",
			(int)tv.tv_sec - startsecs, g_samples_matched, g_samples_unmatched);
		fflush(stderr);

                /* Poll on the epoll instance */
                nfds = epoll_wait(bpf_info.epoll_fd, events, MAX_EPOLL_EVENTS, 100);
                if (nfds == -1) {
                        fprintf(stderr, "There was an error calling epoll_wait. Aborting.\n");
                        exit(1);
                }
                if (nfds == 0) {
                        continue;
                }
                printf("There are %d fds ready to be read.\n", nfds);
                for (i = 0; i < nfds; i++) {
                        printf("Got fd %d\n", events[i].data.fd);
                        handle_fd_read(&events[i]);
                }
	}

cleanup:
	close(eustall_info.perf_fd);
	deinit_bpf_i915();

	return NULL;
}

int start_collect_thread()
{
	int retval;

	retval = pthread_create(&collect_thread_id, NULL, &collect_thread_main,
				NULL);
	if (retval != 0) {
		fprintf(stderr,
			"Failed to call pthread_create. Something is very wrong. Aborting.\n");
		return -1;
	}

	return 0;
}

/*******************
*      SIDECAR     *
*******************/

void *sidecar_thread_main(void *a)
{
	system(g_sidecar);
	return NULL;
}

int start_sidecar_thread()
{
	int retval;

	retval = pthread_create(&sidecar_thread_id, NULL, &sidecar_thread_main,
				NULL);
	if (retval != 0) {
		fprintf(stderr,
			"Failed to call pthread_create. Something is very wrong. Aborting.\n");
		return -1;
	}

	return 0;
}

/*******************
*       MAIN       *
*******************/

void stop_main_thread(int sig)
{
	main_thread_should_stop = 1;
}

int main(int argc, char **argv)
{
	struct sigaction sa;
	struct timespec leftover, request = { 1, 0 };
	char *failed_decode = "[failed_decode]";

	read_opts(argc, argv);
	check_permissions();

	/* Begin profiling */
	print_status("Initializing, please wait...\n");
	if (start_collect_thread() != 0) {
		fprintf(stderr,
			"Failed to start the collection thread. Aborting.\n");
		exit(1);
	}
	if (g_sidecar) {
		/* don't kick off the sidecar command until profiling has started */
		while (!collect_thread_profiling) {
			nanosleep(&request, &leftover);
		}
		if (start_sidecar_thread() != 0) {
			fprintf(stderr,
				"Failed to start the provided command. Aborting.\n");
			exit(1);
		}
	}

	sa.sa_flags = 0;
	sa.sa_handler = stop_main_thread;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		fprintf(stderr,
			"Error creating interval signal handler. Aborting.\n");
		exit(1);
	}

	/* The collector thread is starting profiling rougly now.. */
	if (g_sidecar) {
		/* Wait until sidecar command finishes */
		pthread_join(sidecar_thread_id, NULL);
	} else {
		/* Wait until we get a signal (Ctrl-C) */
		while (!main_thread_should_stop) {
			nanosleep(&request, &leftover);
		}
	}
	if (collect_thread_profiling) {
		print_status("\nProfile stopped. Assembling output...\n");
	} else {
		print_status(
			"Exit requested (had not yet started profiling).\n");
	}

	/* Wait for the collection thread to finish */
	stop_collect_thread();
	pthread_join(collect_thread_id, NULL);

	if (verbose) {
		printf("%d samples matched, %d samples unmatched.\n",
		       g_samples_matched, g_samples_unmatched);
	}
	fflush(stdout);

        if (debug) {
                print_debug_profile();
        }
        print_flamegraph();
}
