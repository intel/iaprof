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
#include <errno.h>
#include <fcntl.h>

#include "iaprof.h"

#include "stores/buffer_profile.h"
#include "stores/proto_flame.h"

/* Helpers */
#include "drm_helpers/drm_helpers.h"
#include "i915_helpers/i915_helpers.h"

/* Collectors */
#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/bpf_i915/bpf/main.h"
#include "collectors/bpf_i915/bpf/main.skel.h"
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
char debug_collector = 1;
char *g_sidecar = NULL;

pthread_mutex_t debug_print_lock = PTHREAD_MUTEX_INITIALIZER;

static struct option long_options[] = { { "debug", no_argument, 0, 'd' },
                                        { "help", no_argument, 0, 'h' },
                                        { "quiet", no_argument, 0, 'q' },
                                        { "verbose", no_argument, 0, 'v' },
                                        { "batchbuffer-debug", no_argument, 0,
                                          'b' },
                                        { "no-debug-collector", no_argument, 0, 'g' },
                                        { "version", no_argument, 0, 0 },
                                        { 0 } };

void usage()
{
        printf("USAGE: iaprof [-dhqv] [command]\n\n");
        printf(" e.g.:\n");
        printf("        iaprof > profile.txt            # profile until Ctrl-C.\n");
        printf("        iaprof sleep 30 > profile.txt   # profile for 30 seconds.\n");
        printf("\noptional arguments:\n");
        printf("        -d, --debug              debug\n");
        printf("        -b, --batchbuffer-debug  debug the parsing of batchbuffers\n");
        printf("        -g, --no-debug-collector disable the i915 debugger\n");
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
                c = getopt_long(argc, argv, "dbghqv", long_options,
                                &option_index);
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
                case 'g':
                        debug_collector = 0;
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
                        size += strlen(argv[i]) + 2; /* Make room for trailing space and NULL terminator. */
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
*       UI         *
*******************/

void print_number(uint64_t num)
{
        if (num >= 1000000) {
                fprintf(stderr, "%8zum", num / 1000000);
        } else if (num > 1000) {
                fprintf(stderr, "%8zuk", num / 1000);
        } else {
                fprintf(stderr, "%9zu", num);
        }
}

int first = 1;

void print_table()
{
        if (isatty(STDERR_FILENO) && !first) {
                fprintf(stderr,
                        "\x1B"
                        "[%dA",
                        7);
        } else {
                first = 0;
        }
        fprintf(stderr, "|--------------------------------------------|\n");
        fprintf(stderr, "|                    Stalls                  |\n");
        fprintf(stderr, "|--------------------------------------------|\n");
        fprintf(stderr, "|  Matched  |  Unmatched/Pending |  Guessed  |\n");
        fprintf(stderr, "|--------------------------------------------|\n");
        fprintf(stderr, "| ");
        print_number(eustall_info.matched);
        fprintf(stderr, " |          ");
        pthread_mutex_lock(&eustall_waitlist_mtx);
        print_number(array_len(*eustall_waitlist));
        pthread_mutex_unlock(&eustall_waitlist_mtx);
        fprintf(stderr, " | ");
        print_number(eustall_info.guessed);
        fprintf(stderr, " |\n");
        fprintf(stderr, "|--------------------------------------------|\n");
        fflush(stderr);
}

void print_status_table(int seconds)
{
        if (quiet || verbose || debug)
                return;

        print_table();
}

/*******************
*     COLLECT      *
*******************/

/* Collector info */
struct device_info devinfo = {};

/* No thread race protection needed. Only accessed in bpf_collect_thread */
struct bpf_info_t bpf_info = {};

struct eustall_info_t eustall_info = {};


#define MAX_EPOLL_EVENTS 64

/* Thread and interval */

enum {
    STOP_REQUESTED  = (1 << 0),
    EUSTALL_DONE    = (1 << 1),
    BPF_DONE        = (1 << 2),
    DEBUG_i915_DONE = (1 << 3),
    STOP_NOW        = (STOP_REQUESTED | EUSTALL_DONE | BPF_DONE | DEBUG_i915_DONE),
};

pthread_t bpf_collect_thread_id;
pthread_t debug_i915_collect_thread_id;
pthread_t eustall_collect_thread_id;
pthread_t eustall_deferred_attrib_thread_id;
pthread_t sidecar_thread_id;
timer_t interval_timer;
static _Atomic char collect_threads_should_stop = 0;
static _Atomic char collect_threads_profiling = 0;
static _Atomic char main_thread_should_stop = 0;

void stop_collect_threads()
{
        collect_threads_should_stop = 1;
}

void add_to_epoll_fd(int fd)
{
        struct epoll_event e = {};

        e.events = EPOLLIN;
        e.data.fd = fd;
        if (epoll_ctl(bpf_info.epoll_fd, EPOLL_CTL_ADD, fd, &e) < 0) {
                fprintf(stderr,
                        "Failed to add to the ringbuffer's epoll instance. Aborting.\n");
                exit(1);
        }
}

void init_driver()
{
        int retval;

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

}

int handle_eustall_read(int fd)
{
        int len;

        /* eustall collector */
        len = read(fd, eustall_info.perf_buf,
                   DEFAULT_USER_BUF_SIZE);
        if (len > 0) {
                handle_eustall_samples(eustall_info.perf_buf, len);
        }

        if (debug) {
                print_debug_profile();
        }
        store_interval_flames();

        /* Reset for the next interval */
        clear_interval_profiles();
        clear_unbound_buffers();

        return 0;
}

void *eustall_deferred_attrib_thread_main(void *a) {
        while (!collect_threads_should_stop) {
                pthread_mutex_lock(&eustall_deferred_attrib_cond_mtx);
                pthread_cond_wait(&eustall_deferred_attrib_cond, &eustall_deferred_attrib_cond_mtx);
                pthread_mutex_unlock(&eustall_deferred_attrib_cond_mtx);

                handle_deferred_eustalls();
        }

        return NULL;
}

void *eustall_collect_thread_main(void *a) {
        sigset_t      mask;
        struct pollfd pollfd;
        int           n_ready;
        int           flags;

        /* The collect thread should block SIGINT, so that all
           SIGINTs go to the main thread. */
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
                fprintf(stderr, "Error blocking signal. Aborting.\n");
                goto out;
        }

        /* EU stall collector. Add to the epoll_fd that the bpf_i915
           collector created. */
        if (init_eustall(&devinfo)) {
                fprintf(stderr, "Failed to configure EU stalls. Aborting!\n");
                goto out;
        }

        collect_threads_profiling += 1;

        pollfd.fd     = eustall_info.perf_fd;
        pollfd.events = POLLIN;

        flags = fcntl(pollfd.fd, F_GETFL, 0);
        fcntl(pollfd.fd, F_SETFL, flags | O_NONBLOCK);

        while (collect_threads_should_stop == 0) {
                n_ready = poll(&pollfd, 1, 100);

                if (n_ready < 0) {
                        switch (errno) {
                                case EINTR:
                                        /* poll was interrupted. Just try again. */
                                        errno = 0;
                                        goto next;
                                default:
                                        fprintf(stderr, "ERROR: poll failed with fatal error %d.\n", errno);
                                        goto out;
                        }
                }



                if (n_ready) {
                        if (main_thread_should_stop != STOP_NOW) {
                                main_thread_should_stop &= ~EUSTALL_DONE;
                        }
                        handle_eustall_read(pollfd.fd);
                } else {
                        if (main_thread_should_stop) {
                                main_thread_should_stop |= EUSTALL_DONE;
                        }
                }
next:;
        }

out:;
        return NULL;
}

void *bpf_collect_thread_main(void *a) {
        sigset_t mask;
        struct pollfd pollfd;
        int n_ready;
        int retval;

        /* The collect thread should block SIGINT, so that all
           SIGINTs go to the main thread. */
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
                fprintf(stderr, "Error blocking signal. Aborting.\n");
                goto out;
        }

        init_bpf_i915();

        collect_threads_profiling += 1;

        /* bpf_i915 collector. Note that libbpf sets event->data.fd to
           ring_cnt, which, because we only have one ringbuffer, is zero. */

        pollfd.fd = bpf_info.rb_fd;
        pollfd.events = POLLIN;

        while (collect_threads_should_stop == 0) {
                n_ready = poll(&pollfd, 1, 100);

                if (n_ready < 0) {
                        switch (errno) {
                                case EINTR:
                                        /* poll was interrupted. Just try again. */
                                        n_ready = 0;
                                        break;
                                default:
                                        fprintf(stderr, "ERROR: poll failed with fatal error %d.\n", errno);
                                        goto out_deinit;
                        }
                        errno = 0;
                }

                if (n_ready) {
                        if (main_thread_should_stop != STOP_NOW) {
                                main_thread_should_stop &= ~BPF_DONE;
                        }

                        retval = ring_buffer__consume(bpf_info.rb);
                        if (retval < 0) {
                                fprintf(stderr,
                                        "WARNING: ring_buffer__consume failed.\n");
                        }
                } else {
                        if (main_thread_should_stop) {
                                main_thread_should_stop |= BPF_DONE;
                        }
                }
        }

out_deinit:;
        deinit_bpf_i915();

out:;
        return NULL;
}

void *debug_i915_collect_thread_main(void *a) {
        sigset_t      mask;
        int           n_fds;
        struct pollfd pollfds[MAX_PIDS];
        int           n_ready;
        int           i;

        /* The collect thread should block SIGINT, so that all
           SIGINTs go to the main thread. */
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
                fprintf(stderr, "Error blocking signal. Aborting.\n");
                return NULL;
        }

        collect_threads_profiling += 1;

        while (collect_threads_should_stop == 0) {
                /* Copy the pollfds array from debug_i915_info so that we don't
                 * need to hold the lock while we poll. */
                pthread_rwlock_rdlock(&debug_i915_info_lock);
                n_fds = debug_i915_info.num_pids;
                memcpy(pollfds, debug_i915_info.pollfds, n_fds * sizeof(struct pollfd));
                pthread_rwlock_unlock(&debug_i915_info_lock);

                n_ready = poll(pollfds, n_fds, 100);

                if (n_ready < 0) {
                        switch (errno) {
                                case EINTR:
                                        /* poll was interrupted. Just try again. */
                                        n_ready = 0;
                                        break;
                                default:
                                        fprintf(stderr, "ERROR: poll failed with fatal error %d.\n", errno);
                                        goto out;
                        }
                        errno = 0;
                }

                if (n_ready) {
                        if (main_thread_should_stop != STOP_NOW) {
                                main_thread_should_stop &= ~DEBUG_i915_DONE;
                        }

                        if (!debug_collector && debug) {
                                fprintf(stderr, "WARNING: GPU symbols were disabled, but we got a debug_i915 event.\n");
                        }

                        for (i = 0; i < n_fds; i += 1) {
                                if (pollfds[i].revents == POLLIN) {
                                        /* We don't hold the debug_i915_info_lock at
                                         * this point going down this call stack, but
                                         * it may get grabbed within it (e.g. by
                                         * debug_i915_add_sym). */
                                        read_debug_i915_events(pollfds[i].fd, i);
                                }
                        }
                } else {
                        if (main_thread_should_stop) {
                                main_thread_should_stop |= DEBUG_i915_DONE;
                        }
                }
        }

out:;
        return NULL;
}

int start_bpf_collect_thread()
{
        int retval;

        retval = pthread_create(&bpf_collect_thread_id, NULL, &bpf_collect_thread_main,
                                NULL);
        if (retval != 0) {
                fprintf(stderr,
                        "Failed to call pthread_create. Something is very wrong. Aborting.\n");
                return -1;
        }

        return 0;
}

int start_debug_i915_collect_thread()
{
        int retval;

        retval = pthread_create(&debug_i915_collect_thread_id, NULL, &debug_i915_collect_thread_main,
                                NULL);
        if (retval != 0) {
                fprintf(stderr,
                        "Failed to call pthread_create. Something is very wrong. Aborting.\n");
                return -1;
        }

        return 0;
}

int start_eustall_collect_thread()
{
        int retval;

        retval = pthread_create(&eustall_collect_thread_id, NULL, &eustall_collect_thread_main,
                                NULL);
        if (retval != 0) {
                fprintf(stderr,
                        "Failed to call pthread_create. Something is very wrong. Aborting.\n");
                return -1;
        }

        return 0;
}

int start_eustall_deferred_attrib_thread()
{
        int retval;

        retval = pthread_create(&eustall_deferred_attrib_thread_id, NULL, &eustall_deferred_attrib_thread_main,
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

void handle_sigint(int sig)
{
        if (!main_thread_should_stop) {
            main_thread_should_stop = STOP_REQUESTED;
            fprintf(stderr,
                    "\nCollecting remaining eustalls... signal once more to stop now.\n");
        } else {
            main_thread_should_stop = STOP_NOW;
        }
}

int main(int argc, char **argv)
{
        struct sigaction sa;
        struct timespec leftover, request = { 1, 0 };
        struct timeval tv;
        int startsecs;

        read_opts(argc, argv);
        check_permissions();

        /* Begin profiling */
        print_status("Initializing, please wait...\n");

        init_profiles();
        init_eustall_waitlist();
        init_driver();

        if (verbose) {
                print_header();
        }

        if (start_bpf_collect_thread() != 0) {
                fprintf(stderr,
                        "Failed to start the collection thread. Aborting.\n");
                exit(1);
        }
        if (start_debug_i915_collect_thread() != 0) {
                fprintf(stderr,
                        "Failed to start the collection thread. Aborting.\n");
                exit(1);
        }
        if (start_eustall_collect_thread() != 0) {
                fprintf(stderr,
                        "Failed to start the collection thread. Aborting.\n");
                exit(1);
        }
        if (start_eustall_deferred_attrib_thread() != 0) {
                fprintf(stderr,
                        "Failed to start the eustall deffered attribution thread. Aborting.\n");
                exit(1);
        }

        /* Wait for the collection thread to start */
        while (collect_threads_profiling < 3) {
                nanosleep(&request, &leftover);
        }
        print_status("Profiling, Ctrl-C to exit...\n");

        /* Start the sidecar */
        if (g_sidecar) {
                if (start_sidecar_thread() != 0) {
                        fprintf(stderr,
                                "Failed to start the provided command. Aborting.\n");
                        exit(1);
                }
        }

        sa.sa_flags = 0;
        sa.sa_handler = handle_sigint;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGINT, &sa, NULL) == -1) {
                fprintf(stderr, "Error creating SIGINT handler. Aborting.\n");
                exit(1);
        }

        gettimeofday(&tv, NULL);
        startsecs = (int)tv.tv_sec;

        /* The collector thread is starting profiling roughly now.. */
        if (g_sidecar) {
                /* Wait until sidecar command finishes */
                pthread_join(sidecar_thread_id, NULL);
        } else {
                /* Wait until we get a signal (Ctrl-C) */
                while (main_thread_should_stop != STOP_NOW) {
                        nanosleep(&request, &leftover);

                        gettimeofday(&tv, NULL);

                        if (!main_thread_should_stop) {
                                print_status_table((int)tv.tv_sec - startsecs);
                        }
                }
        }
        if (collect_threads_profiling) {
                print_status("\nProfile stopped. Assembling output...\n");
        } else {
                print_status(
                        "Exit requested (had not yet started profiling).\n");
        }

        /* Wait for the collection thread to finish */
        stop_collect_threads();
        pthread_join(bpf_collect_thread_id, NULL);
        pthread_join(debug_i915_collect_thread_id, NULL);
        pthread_join(eustall_collect_thread_id, NULL);
        wakeup_eustall_deferred_attrib_thread();
        pthread_join(eustall_deferred_attrib_thread_id, NULL);

        print_flamegraph();

        free_profiles();

        fflush(stdout);
}
