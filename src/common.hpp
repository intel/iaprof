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

#pragma once

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <type_traits>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <format>
#include <print>
#include <filesystem>
#include <fstream>
#include <thread>
#include <mutex>
#include <shared_mutex>
#include <condition_variable>
#include <regex>

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/stat.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;
typedef float    f32;
typedef double   f64;

extern bool       debug;
extern std::mutex debug_print_mtx;

#define debug_print(...)                        \
do {                                            \
    if (debug) {                                \
        std::scoped_lock lock(debug_print_mtx); \
        std::print(stderr, __VA_ARGS__);        \
        fflush(stderr);                         \
    }                                           \
} while (0)

#define ERR(_fmt, ...)                          \
do {                                            \
    std::scoped_lock lock(debug_print_mtx);     \
    int _save_errno = errno;                    \
    std::print(stderr, "{}ERROR{}: " _fmt,      \
            isatty(2) ? "\e[0;31m" : "",        \
            isatty(2) ? "\e[00m" : "",          \
            ##__VA_ARGS__);                     \
    fflush(stderr);                             \
    if (_save_errno) { exit(_save_errno); }     \
    exit(1);                                    \
} while (0)

#define ERR_NOEXIT(_fmt, ...)                   \
do {                                            \
    std::scoped_lock lock(debug_print_mtx);     \
    std::print(stderr, "{}ERROR{}: " _fmt,      \
            isatty(2) ? "\e[0;31m" : "",        \
            isatty(2) ? "\e[00m" : "",          \
            ##__VA_ARGS__);                     \
    fflush(stderr);                             \
} while (0)

#define WARN(_fmt, ...)                         \
do {                                            \
    std::scoped_lock lock(debug_print_mtx);     \
    std::print(stderr, "{}WARNING{}: " _fmt,    \
            isatty(2) ? "\e[0;33m" : "",        \
            isatty(2) ? "\e[00m" : "",          \
            ##__VA_ARGS__);                     \
    fflush(stderr);                             \
} while (0)

#define INFO(_fmt, ...)                         \
do {                                            \
    std::scoped_lock lock(debug_print_mtx);     \
    std::print(stderr, "{}INFO{}: " _fmt,       \
            isatty(2) ? "\e[0;36m" : "",        \
            isatty(2) ? "\e[00m" : "",          \
            ##__VA_ARGS__);                     \
    fflush(stderr);                             \
} while (0)



// Source - https://stackoverflow.com/a/4027734

// Posted by GManNickG, modified by community. See post 'Timeline' for change history

// Retrieved 2026-02-27, License - CC BY-SA 4.0
template <typename T>
class auto_cast_wrapper
{
public:
    template <typename R>
    friend auto_cast_wrapper<R> auto_cast(const R& x);

    template <typename U>
    operator U()
    {
        return static_cast<U>(mX);
    }

private:
    auto_cast_wrapper(const T& x) :
    mX(x)
    {}

    auto_cast_wrapper(const auto_cast_wrapper& other) :
    mX(other.mX)
    {}

    // non-assignable
    auto_cast_wrapper& operator=(const auto_cast_wrapper&);

    const T& mX;
};

template <typename R>
auto_cast_wrapper<R> auto_cast(const R& x)
{
    return auto_cast_wrapper<R>(x);
}
