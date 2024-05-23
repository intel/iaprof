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
#include <sys/time.h>

#include "iaprof.h"

#include "common.h"
#include "utils/utils.h"
#include "drm_helper.h"

#include "eustall_collector.h"
#include "shader_decoder.h"
#include "bpf/gem_collector.h"
#include "bpf/gem_collector.skel.h"
#include "event_collector.h"
#include "flamegraph_printer.h"
#include "printer.h"

/*******************
* COMMANDLINE ARGS *
*******************/

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "?"
#endif
int pid = 0;
char verbose = 0;
char debug = 0;
char quiet = 0;
char *g_sidecar = NULL;
int g_samples_matched = 0;
int g_samples_unmatched = 0;

static struct option long_options[] = {
	{ "debug", no_argument, 0, 'd' }, { "help", no_argument, 0, 'h' },
	{ "quiet", no_argument, 0, 'q' }, { "verbose", no_argument, 0, 'v' },
	{ "version", no_argument, 0, 0 }, { 0 }
};

void usage()
{
	printf("USAGE: iaprof [-dhqv] [command]\n\n");
	printf(" e.g.:\n");
	printf("        iaprof > profile.txt            # profile until Ctrl-C.\n");
	printf("        iaprof sleep 30 > profile.txt   # profile for 30 seconds.\n");
	printf("\noptional arguments:\n");
	printf("        -d, --debug     debug\n");
	printf("        -h, --help      help\n");
	printf("        -q, --quiet     quiet\n");
	printf("        -v, --verbose   verbose\n");
	printf("        command         profile system-wide while command runs\n\n");
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
		c = getopt_long(argc, argv, "dhv", long_options, &option_index);
		if (c == -1) {
			break;
		}
		switch (c) {
		case 'd':
			debug = 1;
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

/* XXX This is a nasty hack! We're using a ringbuffer to send structs
   from the BPF program to userspace. We're not just using one type of
   struct, though; we're using a separate struct type per type of event.
   Because reading a ringbuffer sample doesn't give you the *type*, just
   a *size*, the only way to differentiate these samples is by their size.
   
   Therefore, we need to ensure that none of the structs that will be
   placed in the ringbuffer are the same size. We do this with this
   long list of assertions.
   
   Perhaps I should quarantine this into a separate file...? */
void sanity_checks()
{
	static_assert(sizeof(struct mapping_info) != sizeof(struct unmap_info),
		      "mapping_info is the same size as unmap_info");
	static_assert(sizeof(struct mapping_info) !=
			      sizeof(struct userptr_info),
		      "mapping_info is the same size as userptr_info");
	static_assert(sizeof(struct mapping_info) !=
			      sizeof(struct vm_bind_info),
		      "mapping_info is the same size as vm_bind_info");
	static_assert(sizeof(struct mapping_info) !=
			      sizeof(struct vm_unbind_info),
		      "mapping_info is the same size as vm_unbind_info");
	static_assert(sizeof(struct mapping_info) !=
			      sizeof(struct execbuf_start_info),
		      "mapping_info is the same size as execbuf_start_info");
	static_assert(sizeof(struct mapping_info) !=
			      sizeof(struct execbuf_end_info),
		      "mapping_info is the same size as execbuf_end_info");

	static_assert(sizeof(struct unmap_info) != sizeof(struct userptr_info),
		      "unmap_info is the same size as userptr_info");
	static_assert(sizeof(struct unmap_info) != sizeof(struct vm_bind_info),
		      "unmap_info is the same size as vm_bind_info");
	static_assert(sizeof(struct unmap_info) !=
			      sizeof(struct vm_unbind_info),
		      "unmap_info is the same size as vm_unbind_info");
	static_assert(sizeof(struct unmap_info) !=
			      sizeof(struct execbuf_start_info),
		      "unmap_info is the same size as execbuf_start_info");
	static_assert(sizeof(struct unmap_info) !=
			      sizeof(struct execbuf_end_info),
		      "unmap_info is the same size as execbuf_end_info");

	static_assert(sizeof(struct userptr_info) !=
			      sizeof(struct vm_bind_info),
		      "userptr_info is the same size as vm_bind_info");
	static_assert(sizeof(struct userptr_info) !=
			      sizeof(struct vm_unbind_info),
		      "userptr_info is the same size as vm_unbind_info");
	static_assert(sizeof(struct userptr_info) !=
			      sizeof(struct execbuf_start_info),
		      "userptr_info is the same size as execbuf_start_info");
	static_assert(sizeof(struct userptr_info) !=
			      sizeof(struct execbuf_end_info),
		      "userptr_info is the same size as execbuf_end_info");

	static_assert(sizeof(struct vm_bind_info) !=
			      sizeof(struct vm_unbind_info),
		      "vm_bind_info is the same size as vm_unbind_info");
	static_assert(sizeof(struct vm_bind_info) !=
			      sizeof(struct execbuf_start_info),
		      "vm_bind_info is the same size as execbuf_start_info");
	static_assert(sizeof(struct vm_bind_info) !=
			      sizeof(struct execbuf_end_info),
		      "vm_bind_info is the same size as execbuf_end_info");

	static_assert(sizeof(struct vm_unbind_info) !=
			      sizeof(struct execbuf_start_info),
		      "vm_unbind_info is the same size as execbuf_start_info");
	static_assert(sizeof(struct vm_unbind_info) !=
			      sizeof(struct execbuf_end_info),
		      "vm_unbind_info is the same size as execbuf_end_info");

	static_assert(
		sizeof(struct execbuf_start_info) !=
			sizeof(struct execbuf_end_info),
		"execbuf_start_info is the same size as execbuf_end_info");
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

struct bpf_info_t bpf_info = {};
int perf_fd;
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

/* Checks for eustalls ready to be read */
enum eustall_status poll_eustalls(int perf_fd, uint8_t *perf_buf)
{
        int retval, len;
	enum eustall_status status;
	struct pollfd pollfd = {
		.events = POLLIN,
	};

	pollfd.fd = perf_fd;
	retval = poll(&pollfd, 1, 1);
	if (retval < 0) {
		fprintf(stderr,
		        "An error occurred while reading the EU stall file descriptor! Aborting.\n");
		return EUSTALL_STATUS_ERROR;
	} else if (retval > 0) {
		/* There are samples to read */
		len = read(perf_fd, perf_buf, p_user);
		if (len > 0) {
			return handle_eustall_samples(perf_buf, len);
		}
	}

        return EUSTALL_STATUS_OK;
}

void *collect_thread_main(void *a)
{
	uint8_t *perf_buf;
	int perf_fd, i, startsecs;
	struct timeval tv;
	sigset_t mask;
        enum eustall_status status;

	/* The collect thread should block SIGINT, so that all
     SIGINTs go to the main thread. */
	sigemptyset(&mask);
	sigaddset(&mask, SIGINT);
	if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
		fprintf(stderr, "Error blocking signal. Aborting.\n");
		return NULL;
	}

	/* Initialize the BPF program */
	init_bpf_prog();

	/* Initialize the EU stall collection */
	perf_fd = configure_eustall();
	if (perf_fd < 0) {
		fprintf(stderr, "Failed to configure EU stalls. Aborting!\n");
		exit(1);
	}
	if (collect_thread_should_stop == 0)
		print_status("Profiling... Ctrl-C to end.\n");
	if (verbose)
		print_header();
	collect_thread_profiling = 1;
	perf_buf = malloc(p_user);

	gettimeofday(&tv, NULL);
	startsecs = (int)tv.tv_sec;

	while (collect_thread_should_stop == 0) {
		gettimeofday(&tv, NULL);
		/* Check if there are eustalls */
		fprintf(stderr,
			"\rStatus: profiling for %d secs, %d samples matched, %d samples unmatched. ",
			(int)tv.tv_sec - startsecs, g_samples_matched, g_samples_unmatched);
		fflush(stderr);

                status = poll_eustalls(perf_fd, perf_buf);
                if (status == EUSTALL_STATUS_ERROR) {
                        goto cleanup;
                }

		/* Sit for a bit on the GEM info ringbuffer */
		ring_buffer__poll(bpf_info.rb, 100);
	}

	/* Once we've been told to clean up, check one last time */
	ring_buffer__poll(bpf_info.rb, 1);
        status = poll_eustalls(perf_fd, perf_buf);
        if (status == EUSTALL_STATUS_ERROR) {
                goto cleanup;
        }

cleanup:
	free(perf_buf);
	close(perf_fd);
	deinit_bpf_prog();

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

	sanity_checks();
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

        print_flamegraph();
}
