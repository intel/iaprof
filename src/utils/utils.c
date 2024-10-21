#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "iaprof.h"
#include "utils/utils.h"

#define MAX_CHARS_ADDR 16

uint64_t next_power_of_2(uint64_t x) {
    if (x == 0) {
        return 2;
    }

    x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;
    x |= x >> 32;
    x++;
    return x;
}

void find_elf_magic_bytes(pid_t pid, char debug)
{
        FILE *mem_file;
        char filename[256], line[256], start_addr_str[MAX_CHARS_ADDR + 1],
                end_addr_str[MAX_CHARS_ADDR + 1];
        int i, n;
        unsigned char *buf;
        unsigned long start_addr, end_addr;
        uint64_t size;

        /* Open the memory map */
        sprintf(filename, "/proc/%ld/maps", (long)pid);
        mem_file = fopen(filename, "r");
        if (!mem_file) {
                fprintf(stderr, "Failed to open %s!\n", filename);
                return;
        }

        while (fgets(line, sizeof(line), mem_file)) {
                /* Copy until we hit the '-', or until MAX_CHARS_ADDR characters */
                i = 0;
                while (i < MAX_CHARS_ADDR) {
                        if ((i == MAX_CHARS_ADDR + 1) || (line[i] == '-')) {
                                start_addr_str[i] = 0;
                                break;
                        }
                        start_addr_str[i] = line[i];
                        i++;
                }
                i++;
                n = 0;
                while (n < MAX_CHARS_ADDR) {
                        if ((n == MAX_CHARS_ADDR + 1) || (line[i + n] == '-')) {
                                end_addr_str[n] = 0;
                                break;
                        }
                        end_addr_str[n] = line[i + n];
                        n++;
                }
                start_addr = strtoul(start_addr_str, NULL, 16);
                end_addr = strtoul(end_addr_str, NULL, 16);
                size = end_addr - start_addr;
                if (start_addr && end_addr) {
                        buf = copy_buffer(pid, (uint64_t)start_addr, 4, debug);
                        if (!buf)
                                continue;
                        if (*((uint32_t *)buf) == 0x464c457f) {
                                debug_printf("Reading from 0x%lx - 0x%lx...\n",
                                                start_addr, end_addr);
                                free(buf);
                                buf = copy_buffer(pid, (uint64_t)start_addr,
                                                  size, debug);
                        }
                        free(buf);
                }
        }

        fclose(mem_file);
        fflush(stdout);
}

int handle_binary(unsigned char **dst, unsigned char *src, uint64_t *dst_sz,
                  uint64_t src_sz)
{
        if (!src_sz || !src)
                return -1;
        if (*dst == src) {
                fprintf(stderr, "WARNING: Trying to copy a buffer into itself.\n");
                return -1;
        }

        *dst = realloc(*dst, src_sz);
        memcpy(*dst, src, src_sz);
        *dst_sz = src_sz;

        if (debug) {
                debug_printf("handle_binary\n");
        }

        return 0;
}

int handle_binary_from_fd(int fd, unsigned char **buf, size_t size, uint64_t gpu_addr)
{
        ssize_t bytes_read;
        size_t should_read, retry_size;
        uint8_t max_retries, retry;
        unsigned char *ptr;

        /* Allocate */
        *buf = realloc(*buf, size);
        if (!(*buf))  {
                fprintf(stderr, "WARNING: Failed to allocate %zu bytes.\n", size);
                return -1;
        }

        /* Sync */
        fsync(fd);

        /* Read */
        should_read = size;
        retry_size = size;
        max_retries = 3;
        retry = 0;
        ptr = *buf;
        do {
                debug_printf("Reading from gpu_addr=0x%lx\n", gpu_addr);
                bytes_read = pread(fd, ptr, should_read, gpu_addr);

                gpu_addr += bytes_read;
                ptr += bytes_read;
                should_read -= bytes_read;

                if (bytes_read == 0) {
                        if (should_read < retry_size) {
                                retry = 0;
                        }
                        retry++;
                        retry_size = should_read;
                }
        } while (((bytes_read == 0) && (retry < max_retries)) || ((bytes_read > 0) && (should_read > 0)));

        /* Sync again */
        fsync(fd);

        return 0;
}

#define MAX_DUPLICATES 4096
void dump_buffer(unsigned char *kernel, uint64_t size, uint64_t id)
{
        char filename[256];
        unsigned int i;
        FILE *tmpfile;

        for (i = 0; i < MAX_DUPLICATES; i++) {
                sprintf(filename, "/tmp/iaprof_%lu_%u.bin", id, i);
                tmpfile = fopen(filename, "r");
                if (tmpfile) {
                        /* This file already exists, so go to the next filename */
                        fclose(tmpfile);
                        if (i == (MAX_DUPLICATES - 1)) {
                                fprintf(stderr,
                                        "WARNING: Hit MAX_DUPLICATES.\n");
                                return;
                        }
                } else {
                        break;
                }
        }

        debug_printf("Writing ID %lu to %s\n", id, filename);
        tmpfile = fopen(filename, "w");
        if (!tmpfile) {
                fprintf(stderr, "WARNING: Failed to open %s\n", filename);
                return;
        }
        fwrite(kernel, sizeof(unsigned char), size, tmpfile);
        fclose(tmpfile);
}

void print_map(pid_t pid)
{
        FILE *mem_file;
        char filename[256];

        /* Open the memory map */
        sprintf(filename, "/proc/%ld/maps", (long)pid);
        mem_file = fopen(filename, "r");
        if (!mem_file) {
                fprintf(stderr, "Failed to open %s!\n", filename);
                return;
        }

        char line[256];
        while (fgets(line, sizeof(line), mem_file)) {
                printf("%s", line);
        }
        fclose(mem_file);
        fflush(stdout);
}

unsigned char *copy_buffer(uint32_t pid, uint64_t ptr, uint64_t size,
                           char debug)
{
        size_t num_read;
        FILE *mem_file;
        char filename[256];
        int retval;
        unsigned char *data;

        /* Open the memory map */
        sprintf(filename, "/proc/%u/mem", pid);
        mem_file = fopen(filename, "r");
        if (!mem_file) {
                return NULL;
        }

        /* Seek to the spot in the application's address space */
        retval = fseeko(mem_file, ptr, SEEK_SET);
        if (retval != 0) {
                fclose(mem_file);
                return NULL;
        }

        /* Allocate room */
        data = calloc(size, sizeof(unsigned char));

        /* Read the data */
        num_read = fread(data, 1, size, mem_file);
        if (num_read != size) {
                if (ferror(mem_file)) {
                        fclose(mem_file);
                        free(data);
                        return NULL;
                } else if (feof(mem_file)) {
                        fclose(mem_file);
                        free(data);
                        return NULL;
                }
        }
        fclose(mem_file);

        return data;
}

uint64_t str_hash(char *s) {
    unsigned long hash = 5381;
    int c;

    while ((c = *s++))
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

int str_equ(char *a, char *b) { return strcmp(a, b) == 0; }
