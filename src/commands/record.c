/*******************************************************************************
 * Record Command
 ****************
 * This command records profiling data and stores it to disk.
*******************************************************************************/

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

/* Collectors */
#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf/bpf_collector.h"
#include "collectors/bpf/bpf/main.h"
#include "collectors/bpf/bpf/main.skel.h"
#include "collectors/debug/debug_collector.h"

/* Driver helpers */
#include "drm_helpers/drm_helpers.h"
#if GPU_DRIVER == GPU_DRIVER_xe
#include "driver_helpers/xe_helpers.h"
#elif GPU_DRIVER == GPU_DRIVER_i915
#include "driver_helpers/i915_helpers.h"
#endif

/* Printers */
#include "printers/stack/stack_printer.h"
#include "printers/debug/debug_printer.h"
#include "printers/interval/interval_printer.h"

/* Stores */
#include "stores/gpu_kernel.h"

#include "commands/record.h"

/******************
 * GLOBALS        *
 ******************/
enum {
    STOP_REQUESTED  = (1 << 0),
    EUSTALL_DONE    = (1 << 1),
    BPF_DONE        = (1 << 2),
    DEBUG_DONE      = (1 << 3),
    STOP_NOW        = (STOP_REQUESTED | EUSTALL_DONE | BPF_DONE | DEBUG_DONE),
};
static _Atomic char collect_threads_should_stop = 0;
static _Atomic char collect_threads_profiling = 0;
static _Atomic char collect_threads_enabled = 3;
static _Atomic char main_thread_should_stop = 0;
static _Atomic char eustall_deferred_attrib_thread_should_stop = 0;

/* Intervals */
struct timespec interval_start, interval_end, interval_diff;
static uint64_t interval_number = 0;
static uint32_t interval_time_ms = 500;

enum { NS_PER_SECOND = 1000000000 };
void sub_timespec(struct timespec *t1, struct timespec *t2, struct timespec *td)
{
    td->tv_nsec = t2->tv_nsec - t1->tv_nsec;
    td->tv_sec  = t2->tv_sec - t1->tv_sec;
    if (td->tv_sec > 0 && td->tv_nsec < 0) {
            td->tv_nsec += NS_PER_SECOND;
            td->tv_sec--;
    }
    else if (td->tv_sec < 0 && td->tv_nsec > 0) {
            td->tv_nsec -= NS_PER_SECOND;
            td->tv_sec++;
    }
}
uint32_t timespec_to_ms(struct timespec *t1)
{
  return ((t1->tv_sec * 1000) + (t1->tv_nsec / 1000000));
}

/*******************
* COMMANDLINE ARGS *
*******************/

int pid = 0;
char bb_debug = 0;
char quiet = 0;
char eudebug_collector = 1;

static struct option long_options[] = { { "debug", no_argument, 0, 'd' },
                                        { "help", no_argument, 0, 'h' },
                                        { "quiet", no_argument, 0, 'q' },
                                        { "batchbuffer-debug", no_argument, 0, 'b' },
                                        { "no-debug-collector", no_argument, 0, 'g' },
                                        { "version", no_argument, 0, 'v' },
                                        { "interval", required_argument, 0, 'i' },
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
        printf("        -g, --no-debug-collector disable the debug interface\n");
        printf("        -h, --help               help\n");
        printf("        -v, --version            version information\n");
        printf("        -q, --quiet              quiet\n");
        printf("        -i, --interval           interval time in milliseconds\n");
        printf("        command                  profile system-wide while command runs\n\n");
        printf("Version: %s\n", GIT_COMMIT_HASH);
}

void check_permissions()
{
        if (geteuid() != 0) {
                ERR("Tool currently needs superuser (root) permission. "
                    "Please consider running with sudo. Exiting.\n");
        }
}

int read_opts(int argc, char **argv)
{
        int option_index;
        char c;

        while (1) {
                option_index = 0;
                c = getopt_long(argc, argv, "dbghi:qv", long_options,
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
                        eudebug_collector = 0;
                        break;
                case 'h':
                        usage();
                        exit(0);
                        /* no fallthrough */
                case 'i':
                        interval_time_ms = strtoul(optarg, NULL, 10);
                        printf("setting interval_time_ms to %u\n", interval_time_ms);
                        break;
                case 'q':
                        quiet = 1;
                        break;
                case 'v':
                        printf("Version: %s\n", GIT_COMMIT_HASH);
                        exit(0);
                case 0:
                        printf("option %s\n",
                               long_options[option_index].name);
                        break;
                }
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
                fprintf(stderr, "%6zum", num / 1000000);
        } else if (num > 1000) {
                fprintf(stderr, "%6zuk", num / 1000);
        } else {
                fprintf(stderr, "%7zu", num);
        }
}

void print_table(int seconds)
{
        if (quiet || debug)
                return;

        if (isatty(STDERR_FILENO)) {
                fprintf(stderr, "\r\e[2K");
        }

        fprintf(stderr, "Matched: ");
        print_number(eustall_info.matched);

        fprintf(stderr, " | Unmatched: ");
        pthread_mutex_lock(&eustall_waitlist_mtx);
        print_number(array_len(*eustall_waitlist));
        pthread_mutex_unlock(&eustall_waitlist_mtx);
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

pthread_t bpf_collect_thread_id;
pthread_t eudebug_collect_thread_id;
pthread_t eustall_collect_thread_id;
pthread_t eustall_deferred_attrib_thread_id;
timer_t interval_timer;

void stop_collect_threads()
{
        collect_threads_should_stop = 1;
}

void init_driver()
{
        int retval;

        /* We'll need the driver for multiple collectors */
        retval = open_first_driver(&devinfo);
        if (retval != 0) {
                ERR("Failed to open any drivers.\n");
        }

        /* Get information about the device */
        if (get_drm_device_info(&devinfo) != 0) {
                ERR("Failed to get device info.\n");
        }

#if GPU_DRIVER == GPU_DRIVER_i915
        if (i915_query_engines(devinfo.fd, &(devinfo.engine_info)) != 0) {
                ERR("Failed to get engine info.\n");
        }
#endif
}

int handle_eustall_read(int fd, struct device_info *devinfo)
{
        int len;

        /* eustall collector */
        len = read(fd, eustall_info.perf_buf,
                   DEFAULT_USER_BUF_SIZE);
        if (len > 0) {
                handle_eustall_samples(eustall_info.perf_buf, len, devinfo);
        }

        return 0;
}

void *eustall_deferred_attrib_thread_main(void *a) {
        while (!eustall_deferred_attrib_thread_should_stop && !collect_threads_should_stop) {
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
                ERR("Error blocking signal.\n");
        }

        /* EU stall collector. Add to the epoll_fd that the bpf
           collector created. */
        if (init_eustall(&devinfo)) {
                ERR("Failed to configure EU stalls.\n");
        }

        if (debug) {
                fprintf(stderr, "Initialized EU stall collector.\n");
        }

        collect_threads_profiling += 1;

        pollfd.fd     = eustall_info.perf_fd;
        pollfd.events = POLLIN;

        flags = fcntl(pollfd.fd, F_GETFL, 0);
        fcntl(pollfd.fd, F_SETFL, flags | O_NONBLOCK);

        /* Initialize the time */
        clock_gettime(CLOCK_MONOTONIC, &interval_start);

        while (collect_threads_should_stop == 0) {
                n_ready = poll(&pollfd, 1, 100);

                /* How long were we asleep...? */
                clock_gettime(CLOCK_MONOTONIC, &interval_end);
                sub_timespec(&interval_start, &interval_end, &interval_diff);
                if (timespec_to_ms(&interval_diff) < interval_time_ms) {
                        /* If we haven't been asleep long enough, go back to sleep! */
                        nanosleep(&interval_diff, NULL);
                        errno = 0;
                        goto next;
                }

                if (n_ready < 0) {
                        switch (errno) {
                                case EINTR:
                                        /* poll was interrupted. Just try again. */
                                        errno = 0;
                                        goto next;
                                default:
                                        ERR("poll failed with fatal error %d.\n", errno);
                        }
                }

                if (n_ready) {
                        if (main_thread_should_stop != STOP_NOW) {
                                main_thread_should_stop &= ~EUSTALL_DONE;
                        }
                        handle_eustall_read(pollfd.fd, &devinfo);
                } else {
                        if (main_thread_should_stop) {
                                main_thread_should_stop |= EUSTALL_DONE;
                        }
                }

                print_interval(interval_number++, NULL);
                clear_interval_profiles();

                clock_gettime(CLOCK_MONOTONIC, &interval_start);
next:;
        }

        eustall_deferred_attrib_thread_should_stop = 1;
        wakeup_eustall_deferred_attrib_thread();
        pthread_join(eustall_deferred_attrib_thread_id, NULL);

        handle_remaining_eustalls();

        pthread_mutex_lock(&eustall_waitlist_mtx);
        print_interval(interval_number++, eustall_waitlist);
        pthread_mutex_unlock(&eustall_waitlist_mtx);

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
                ERR("Error blocking signal.\n");
        }

        init_bpf();
        errno = 0;

        if (debug) {
                fprintf(stderr, "Initialized BPF collector.\n");
        }

        collect_threads_profiling += 1;

        /* bpf collector. Note that libbpf sets event->data.fd to
           ring_cnt, which, because we only have one ringbuffer, is zero. */

        pollfd.fd = bpf_info.rb_fd;
        pollfd.events = POLLIN;

        while (collect_threads_should_stop == 0) {
                n_ready = poll(&pollfd, 1, 10);

                if (n_ready < 0) {
                        switch (errno) {
                                case EINTR:
                                        /* poll was interrupted. Just try again. */
                                        n_ready = 0;
                                        break;
                                default:
                                        ERR("poll failed with fatal error %d.\n", errno);
                        }
                        errno = 0;
                }

                if (n_ready) {
                        if (main_thread_should_stop != STOP_NOW) {
                                main_thread_should_stop &= ~BPF_DONE;
                        }

                        retval = ring_buffer__consume(bpf_info.rb);
                        if (retval < 0) {
                                WARN("ring_buffer__consume failed.\n");
                        }
                } else {
                        if (main_thread_should_stop) {
                                main_thread_should_stop |= BPF_DONE;
                        }
                }
        }

        deinit_bpf();
        deinit_syms_cache();

        return NULL;
}

void *eudebug_collect_thread_main(void *a) {
        sigset_t       mask;
        array_t        pollfds;
        array_t        pollfds_indices;
        int            n_fds;
        int            n_ready;
        int            i;
        struct pollfd *pfd;
        int            index;

        /* The collect thread should block SIGINT, so that all
           SIGINTs go to the main thread. */
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        if (sigprocmask(SIG_SETMASK, &mask, NULL) == -1) {
                ERR("Error blocking signal.\n");
        }

        pollfds         = array_make(struct pollfd);
        pollfds_indices = array_make(int);

        if (debug) {
                fprintf(stderr, "Initialized debug collector.\n");
        }

        collect_threads_profiling += 1;

        while (collect_threads_should_stop == 0) {
                /* Copy the pollfds array from debug_info so that we don't
                 * need to hold the lock while we poll. */
                pthread_rwlock_rdlock(&eudebug_info_lock);

                n_fds = eudebug_info.num_pids;

                array_clear(pollfds);
                array_clear(pollfds_indices);
                for (i = 0; i < n_fds; i += 1) {
                        if (eudebug_info.pollfds[i].fd > 0) {
                                array_push(pollfds, eudebug_info.pollfds[i]);
                                array_push(pollfds_indices, i);
                        }
                }

                pthread_rwlock_unlock(&eudebug_info_lock);

                n_ready = poll(array_data(pollfds), array_len(pollfds), 100);

                if (n_ready < 0) {
                        switch (errno) {
                                case EINTR:
                                        /* poll was interrupted. Just try again. */
                                        n_ready = 0;
                                        break;
                                default:
                                        ERR("poll failed with fatal error %d.\n", errno);
                        }
                        errno = 0;
                }

                if (n_ready) {
                        if (main_thread_should_stop != STOP_NOW) {
                                main_thread_should_stop &= ~DEBUG_DONE;
                        }

                        if (!eudebug_collector && debug) {
                                WARN("GPU symbols were disabled, but we got an eudebug event.\n");
                        }


                        for (i = 0; i < array_len(pollfds); i += 1) {
                                pfd = array_item(pollfds, i);
                                index = *(int*)array_item(pollfds_indices, i);
                                if (pfd->revents & POLLIN) {
                                        /* We don't hold the debug_info_lock at
                                         * this point going down this call stack, but
                                         * it may get grabbed within it (e.g. by
                                         * debug_add_sym). */
                                        read_eudebug_events(pfd->fd, index);
                                } else {
                                        deinit_eudebug(index);
                                }
                        }
                } else {
                        if (main_thread_should_stop) {
                                main_thread_should_stop |= DEBUG_DONE;
                        }
                }
        }

        array_free(pollfds);
        array_free(pollfds_indices);

        return NULL;
}

int start_thread(void *(*fn)(void*), pthread_t *out_pthread) {
        int retval;

        retval = pthread_create(out_pthread, NULL, fn, NULL);
        if (retval != 0) {
                WARN("pthread_create failed.\n");
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
            fprintf(stderr, "\nCollecting remaining eustalls... signal once more to stop now.\n");
        } else {
            main_thread_should_stop = STOP_NOW;
        }
}

void record(int argc, char **argv)
{
        struct sigaction sa;
        struct timespec leftover, request = { 1, 0 };
        struct timeval tv;
        int startsecs;

        read_opts(argc, argv);
        check_permissions();

        /* Begin profiling */
        print_status("Initializing, please wait...\n");

        print_initial_strings();
        init_profiles();
        init_eustall_waitlist();
        init_driver();

        if (start_thread(bpf_collect_thread_main, &bpf_collect_thread_id) != 0) {
                ERR("Failed to start the BPF collection thread.\n");
        }
        if (start_thread(eudebug_collect_thread_main, &eudebug_collect_thread_id) != 0) {
                ERR("Failed to start the eudebug collection thread.\n");
        }
        if (start_thread(eustall_collect_thread_main, &eustall_collect_thread_id) != 0) {
                ERR("Failed to start the eustall collection thread.\n");
        }
        if (start_thread(eustall_deferred_attrib_thread_main, &eustall_deferred_attrib_thread_id) != 0) {
                ERR("Failed to start the eustall deffered attribution thread.\n");
        }

        /* Wait for the collection threads to start */
        while (collect_threads_profiling < collect_threads_enabled) {
                nanosleep(&request, &leftover);
        }
        print_status("Profiling, Ctrl-C to exit...\n");

        sa.sa_flags = 0;
        sa.sa_handler = handle_sigint;
        sigemptyset(&sa.sa_mask);
        if (sigaction(SIGINT, &sa, NULL) == -1) {
                ERR("Error creating SIGINT handler.\n");
        }

        gettimeofday(&tv, NULL);
        startsecs = (int)tv.tv_sec;

        /* Wait until we get a signal (Ctrl-C) */
        while (main_thread_should_stop != STOP_NOW) {
                nanosleep(&request, &leftover);

                gettimeofday(&tv, NULL);

                if (!main_thread_should_stop) {
                        print_table((int)tv.tv_sec - startsecs);
                }

                if (*bpf_info.dropped_event) {
                        ERR("Dropped information in BPF... aborting.\n");
                }
        }

        if (collect_threads_profiling) {
                print_status("Profile stopped. Assembling output...\n");
        } else {
                print_status(
                        "Exit requested (had not yet started profiling).\n");
        }

        /* Wait for the collection thread to finish */
        stop_collect_threads();
        pthread_join(bpf_collect_thread_id, NULL);
        pthread_join(eudebug_collect_thread_id, NULL);
        pthread_join(eustall_collect_thread_id, NULL);
        pthread_join(eustall_deferred_attrib_thread_id, NULL);

        /* Print the final profile */
        if (debug) {
          print_debug_profile();
        }
        gettimeofday(&tv, NULL);
        print_table((int)tv.tv_sec - startsecs);
        fprintf(stderr, "\n");

        free_profiles();
        fflush(stdout);
}
