#pragma once

#include <stdint.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <assert.h>
#include <sys/resource.h>
#include <sys/sysinfo.h>
#include <sys/mman.h>
#include <math.h>

static void parse_origin(int pid, uint64_t origin_inst_addr)
{
	FILE *f;
	char buff[4096];
	char *s;
	char *cur;
	uint64_t cur_start;
	uint64_t start;
	uint64_t end;
	char cur_copy[1024];
	FILE *p;
	unsigned long line_no;

	printf("Trying to open the memory map for PID %d, reading 0x%lx\n", pid,
	       origin_inst_addr);

	snprintf(buff, sizeof(buff), "/proc/%d/maps", pid);
	f = fopen(buff, "r");

	if (f == NULL) {
		return;
	}

	cur = NULL;
	cur_start = 0;

	while (fgets(buff, sizeof(buff), f)) {
		if (buff[strlen(buff) - 1] == '\n') {
			buff[strlen(buff) - 1] = 0;
		}

		if (*buff == 0) {
			continue;
		}

		/* range */
		if ((s = strtok(buff, " ")) == NULL) {
			continue;
		}
		sscanf(s, "%lx-%lx", &start, &end);

		/* perms */
		if ((s = strtok(NULL, " ")) == NULL) {
			continue;
		}
		/* offset */
		if ((s = strtok(NULL, " ")) == NULL) {
			continue;
		}
		/* dev */
		if ((s = strtok(NULL, " ")) == NULL) {
			continue;
		}
		/* inode */
		if ((s = strtok(NULL, " ")) == NULL) {
			continue;
		}

		/* path */
		if ((s = strtok(NULL, " ")) == NULL) {
			continue;
		}
		if (*s != '/') {
			continue;
		}

		if (cur == NULL || strcmp(cur, s)) {
			if (cur != NULL) {
				free(cur);
			}
			cur = strdup(s);
			cur_start = start;
		}
	}

	if (cur != NULL) {
		free(cur);
	}

	fclose(f);
}
