#include <stdint.h>
#include <inttypes.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <pthread.h>
#include <ctype.h>
#include <linux/limits.h>

#define STACK_INCLUDE_TID 0

/* For demangling */
#include <libiberty/demangle.h>

#include "iaprof.h"

#include "bpf_helpers/trace_helpers.h"
#include "utils/utils.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/bpf_i915/bpf/main.skel.h"

#include "printers/stack/stack_printer.h"

#include "utils/hash_table.h"
#include "utils/tree.h"

static struct syms_cache *syms_cache = NULL;
pthread_rwlock_t syms_cache_lock = PTHREAD_RWLOCK_INITIALIZER;
static unsigned long ip[MAX_STACK_DEPTH * sizeof(uint64_t)];

/* A temporary string we can use to store the maximum characters
   necessary to print a hexadecimal uint64_t. */
#define MAX_CHARS_UINT64 19
static char tmp_str[MAX_CHARS_UINT64];

typedef struct sym *sym_ptr;
use_tree(uint64_t, sym_ptr);
typedef tree(uint64_t, sym_ptr) hll_syms_map_t;
use_hash_table(int, hll_syms_map_t);

static hash_table(int, hll_syms_map_t) hll_syms;

static uint64_t pid_hash(int pid) { return pid; }

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

        hll_syms = hash_table_make(int, hll_syms_map_t, pid_hash);

        return 0;
}

static hll_syms_map_t get_hll_syms(int pid) {
        hll_syms_map_t *lookup;
        hll_syms_map_t  map;
        char            tmpfile[128];
        FILE           *f;
        struct sym     *sym;
        int             ret;
        char            buf[PATH_MAX];
        char           *name;

        lookup = hash_table_get_val(hll_syms, pid);
        if (lookup != NULL) {
                map = *lookup;
        } else {
                map = tree_make(uint64_t, sym_ptr);

                snprintf(tmpfile, sizeof(tmpfile), "/tmp/perf-%d.map", pid);
                f = fopen(tmpfile, "r");
                if (f == NULL) {
                        goto out;
                }

                while (true) {
                        sym = malloc(sizeof(*sym));
                        memset(sym, 0, sizeof(*sym));

                        ret = fscanf(f, "%lx %lx %[^\n]", &sym->start, &sym->size, buf);
                        if ((ret == EOF && feof(f)) || ret != 3) {
                                free(sym);
                                break;
                        }

                        name = buf;
                        name = buf;
                        while (isspace(*name)) {
                                name++;
                        }
                        sym->name = strdup(name);

                        tree_insert(map, sym->start, sym);
                }

                hash_table_insert(hll_syms, pid, map);
        }

out:;
        return map;
}

static struct sym *hll_sym(hll_syms_map_t map, uint64_t addr) {
        tree_it(uint64_t, sym_ptr) it;
        struct sym *sym;

        it = tree_gtr(map, addr);
        tree_it_prev(it);

        if (!tree_it_good(it)) {
                return NULL;
        }

        sym = tree_it_val(it);
        if (addr >= sym->start + sym->size) {
                return NULL;
        }

        return sym;
}

void store_stack(int pid, int tid, int stackid, char **stack_str)
{
        const struct syms *syms;
        hll_syms_map_t hll_syms_map;
        const struct sym *sym;
        char tid_buf[64];
        int sfd, i, last_i;
        size_t len, cur_len, new_len;
        const char *to_copy;
        char *dso_name, should_free;
        unsigned long dso_offset;

        if (pthread_rwlock_wrlock(&syms_cache_lock) != 0) {
                fprintf(stderr,
                        "Error grabbing the syms_cache_lock. Aborting.\n");
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
                                "WARNING: Failed to get syms for PID %" PRIu32
                                "\n",
                                pid);
                }
                goto cleanup;
        }
        hll_syms_map = get_hll_syms(pid);

        if (bpf_map_lookup_elem(sfd, &stackid, ip) != 0) {
                *stack_str = strdup("[unknown]");
                goto cleanup;
        }


#if STACK_INCLUDE_TID
        snprintf(tid_buf, sizeof(tid_buf), "%u;", tid);
        *stack_str = strdup(tid_buf);
#else
        (void)tid_buf;
#endif

        /* Start at the last nonzero IP */
        last_i = 0;
        for (i = 0; i < MAX_STACK_DEPTH && ip[i]; i++) {
                last_i = i;
        }

        for (i = last_i; i >= 0; i--) {
                should_free = 0;
                dso_name = NULL;
                sym = syms__map_addr_dso(syms, ip[i], &dso_name, &dso_offset);
                if (sym == NULL) {
                        sym = hll_sym(hll_syms_map, ip[i]);
                }

                cur_len = 0;
                if (*stack_str) {
                        cur_len = strlen(*stack_str);
                }
                if (sym) {
                        to_copy = cplus_demangle(sym->name,
                                                 DMGL_NO_OPTS | DMGL_PARAMS |
                                                         DMGL_AUTO);
                        should_free = 1;
                        if (!to_copy) {
                                to_copy = sym->name;
                                should_free = 0;
                        }
                } else {
                        if (dso_name) {
                                to_copy = dso_name;
                        } else {
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
                        free((void *)to_copy);
                }
        }

cleanup:

        if (pthread_rwlock_unlock(&syms_cache_lock) != 0) {
                fprintf(stderr,
                        "Error unlocking the syms_cache_lock. Aborting.\n");
                exit(1);
        }

        return;
}
