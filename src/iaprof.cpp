/*
Copyright 2026 Intel Corporation

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

#include "common.hpp"
#include "globals.hpp"
#include "bpf.hpp"
#include "eustall.hpp"

static void print_usage(const char *argv0);
static bool parse_args(int argc, char **argv);

int main(int argc, char **argv) {
    if (!parse_args(argc, argv)) {
        print_usage(argv[0]);
        return 1;
    }

    if (geteuid() != 0) {
        ERR("Tool currently needs superuser (root) permission. "
            "Please consider running with sudo. Exiting.\n");
    }

    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGALRM);
    sigprocmask(SIG_BLOCK, &set, NULL);

    timer_t timer;
    timer_create(CLOCK_MONOTONIC, NULL, &timer);
    struct itimerspec its;
    its.it_value.tv_sec  = profile_interval_ms / 1000;
    its.it_value.tv_nsec = (profile_interval_ms % 1000) * 1000000;
    its.it_interval      = its.it_value;



    device_info.init();

    BPF_Collector &bpf_collector = BPF_Collector::get();
    (void)bpf_collector;

    EU_Stall_Collector &eustall_collector = EU_Stall_Collector::get();
    (void)eustall_collector;



    timer_settime(timer, 0, &its, NULL);

    while (true) {
        int sig;
        if (sigwait(&set, &sig) == 0) {
            if (sig == SIGINT) { std::print(stderr, "\n"); break; }
        }

        profile.output_interval();
    }

    return 0;
}

static void print_usage(const char *argv0) {
    std::print(stderr, "USAGE: {} [OPTION...]\n", argv0);
    std::print(stderr, "options:\n");
    std::print(stderr, "    --help                        print this information\n");
    std::print(stderr, "    --version                     version information\n");
    std::print(stderr, "    --interval=INTEGER            profiling interval time in milliseconds (default {})\n", DEFAULT_INTERVAL);
    std::print(stderr, "    --eu-stall-subsample=INTEGER  process one out of every N EU stall samples (default {})\n", DEFAULT_EU_STALL_SUBSAMPLE);
}

static bool parse_args(int argc, char **argv) {
    for (int i = 1; i < argc; i += 1) {
        std::string arg = argv[i];

        if (arg == "--help") {
            print_usage(argv[0]);
            exit(0);
        } else if (arg == "--version") {
            std::print(stderr, "{}\n", IAPROF_VERSION);
            exit(0);
        } else if (arg == "--interval" || arg.compare(0, strlen("--interval="), "--interval=") == 0) {
            try {
                profile_interval_ms = std::stoll(arg.substr(strlen("--interval=")));
            } catch (...) {
                ERR_NOEXIT("expected integer for interval\n");
                return false;
            }
            if (profile_interval_ms <= 0) {
                ERR_NOEXIT("interval must be greater than 0\n");
                return false;
            }
        } else if (arg == "--eu-stall-subsample" || arg.compare(0, strlen("--eu-stall-subsample="), "--eu-stall-subsample=") == 0) {
            try {
                eu_stall_subsample = std::stoll(arg.substr(strlen("--eu-stall-subsample=")));
            } catch (...) {
                ERR_NOEXIT("expected integer for eu-stall-subsample\n");
                return false;
            }
            if (eu_stall_subsample <= 0) {
                ERR_NOEXIT("eu-stall-subsample must be greater than 0\n");
                return false;
            }
        } else {
            ERR_NOEXIT("unrecognized option '{}'\n", arg.c_str());
            return false;
        }
    }

    return true;
}
