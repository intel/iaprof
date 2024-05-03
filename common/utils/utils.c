#define _GNU_SOURCE
#include <stdlib.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <inttypes.h>
#include <stdio.h>

#include "utils/utils.h"

void dump_buffer(unsigned char *kernel, uint64_t size, uint32_t id)
{
	char filename[256];
	unsigned int i;
	FILE *tmpfile;

	for (i = 0; i < 10; i++) {
		sprintf(filename, "/tmp/iaprof_%u_%u.bin", id, i);
		tmpfile = fopen(filename, "r");
		if (tmpfile) {
			/* This file already exists, so go to the next filename */
			fclose(tmpfile);
			if (i == (10 - 1)) {
				fprintf(stderr,
					"WARNING: Hit MAX_DUPLICATES for handle %u.\n",
					id);
				return;
			}
		} else {
			break;
		}
	}

	printf("Writing ID %u to %s\n", id, filename);
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

unsigned char *copy_buffer(uint32_t pid, uint64_t ptr, uint64_t size, char debug)
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
                if (debug) {
        		fprintf(stderr,
        			"WARNING: copy_buffer failed to open /proc/%u/mem!\n",
        			pid);
                }
		return NULL;
	}

	/* Seek to the spot in the application's address space */
	retval = fseeko(mem_file, ptr, SEEK_SET);
	if (retval != 0) {
                if (debug) {
        		fprintf(stderr,
        			"WARNING: copy_buffer failed to seek to 0x%lx!\n", ptr);
                }
		fclose(mem_file);
		return NULL;
	}

	/* Allocate room */
	data = calloc(size, sizeof(unsigned char));

	/* Read the data */
	num_read = fread(data, 1, size, mem_file);
	if (num_read != size) {
		fprintf(stderr, "WARNING: copy_buffer failed to read 0x%lx!\n",
			ptr);
		if (ferror(mem_file)) {
			perror("Error while reading file");
			fclose(mem_file);
			free(data);
			return NULL;
		} else if (feof(mem_file)) {
			perror("End-of-file while reading file");
			fclose(mem_file);
			free(data);
			return NULL;
		}
	}
	fclose(mem_file);

	return data;
}
