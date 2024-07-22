#include <stdint.h>
#include <inttypes.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>

/* For demangling */
#include <libiberty/demangle.h>

#include "iaprof.h"

#include "bpf_helpers/trace_helpers.h"
#include "utils/utils.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/bpf_i915/bpf/main.skel.h"

#include "printers/stack/stack_printer.h"

static struct syms_cache *syms_cache = NULL;
pthread_rwlock_t syms_cache_lock = PTHREAD_RWLOCK_INITIALIZER;
static unsigned long ip[MAX_STACK_DEPTH * sizeof(uint64_t)];

/* A temporary string we can use to store the maximum characters
   necessary to print a hexadecimal uint64_t. */
#define MAX_CHARS_UINT64 19
static char tmp_str[MAX_CHARS_UINT64];

int init_syms_cache()
{
	if (syms_cache == NULL) {
		syms_cache = syms_cache__new(0);
		if (!syms_cache) {
			fprintf(stderr,
				"ERROR: Failed to initialize syms_cache.\n");
			return -1;
		}
	}
	return 0;
}

void store_stack(uint32_t pid, int stackid, char **stack_str)
{
	const struct syms *syms;
	const struct sym *sym;
	int sfd, i, last_i;
	size_t len, cur_len, new_len;
	const char *to_copy;
	char *dso_name, have_reloaded, should_free;
	unsigned long dso_offset;

        if (pthread_rwlock_wrlock(&syms_cache_lock) != 0) {
                fprintf(stderr, "Error grabbing the syms_cache_lock. Aborting.\n");
                exit(1);
        }

	if (pid == 0) {
		*stack_str = strdup("[unknown]");
                goto cleanup;
	}

	sfd = bpf_map__fd(bpf_info.obj->maps.stackmap);
	if (sfd <= 0) {
		fprintf(stderr, "Failed to get stackmap.\n");
		goto cleanup;
	}

	if (init_syms_cache() != 0) {
		goto cleanup;
	}
	syms = syms_cache__get_syms(syms_cache, pid);
	if (!syms) {
                if (debug) {
        		fprintf(stderr,
                                "WARNING: Failed to get syms for PID %" PRIu32 "\n",
                                pid);
                }
		goto cleanup;
	}

	if (bpf_map_lookup_elem(sfd, &stackid, ip) != 0) {
		*stack_str = strdup("[unknown]");
		goto cleanup;
	}

	/* Start at the last nonzero IP */
	last_i = 0;
	for (i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
		last_i = i;
	}
        have_reloaded = 0;

	for (i = last_i; i >= 0; i--) {
retry:
                should_free = 0;
		dso_name = NULL;
		sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
		cur_len = 0;
		if (*stack_str) {
			cur_len = strlen(*stack_str);
		}
		if (sym) {
                        to_copy = cplus_demangle(sym->name, DMGL_NO_OPTS | DMGL_PARAMS | DMGL_AUTO);
                        should_free = 1;
                        if (!to_copy) {
        			to_copy = sym->name;
                                should_free = 0;
                        }
		} else {
			if (dso_name) {
				to_copy = dso_name;
			} else {
                                if (!have_reloaded) {
                                syms_cache__reload_syms(syms_cache, pid);
                                	syms = syms_cache__get_syms(syms_cache, pid);
                                	if (!syms) {
                                if (debug) {
                                		fprintf(stderr,
                                			"WARNING: Failed to get syms for PID %" PRIu32 "\n",
                                			pid);
                                }
                                		goto cleanup;
                                	}
                                have_reloaded = 1;
                                goto retry;
                                }
				memset(tmp_str, 0, MAX_CHARS_UINT64);
				sprintf(tmp_str, "0x%lx", ip[i]);
				to_copy = tmp_str;
			}
		}
		len = strlen(to_copy);
		new_len = cur_len + len + 2;
		*stack_str = realloc(*stack_str, new_len);
		memset(*stack_str + cur_len, 0, new_len - cur_len);
		strcpy(*stack_str + cur_len, to_copy);
		(*stack_str)[new_len - 2] = ';';
                if (should_free) {
                        free((void *) to_copy);
                }
	}

cleanup:

  if (pthread_rwlock_unlock(&syms_cache_lock) != 0) {
    fprintf(stderr, "Error unlocking the syms_cache_lock. Aborting.\n");
    exit(1);
  }

	return;
}
