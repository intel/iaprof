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

/* A temporary string we can use to store the maximum characters
   necessary to print a hexadecimal uint64_t. */
#define MAX_CHARS_UINT64 19
static char tmp_str[MAX_CHARS_UINT64];

typedef char *string;
use_hash_table(uint64_t, string);
static hash_table(uint64_t, string) stacks;

use_hash_table(uint64_t, char);
typedef hash_table(uint64_t, char) blacklist_t;
use_hash_table(int, blacklist_t);

static hash_table(int, blacklist_t) blacklists;

/* @TODO: put a lock around hll_syms to that multiple threads may use store_stack(). */

typedef struct sym *sym_ptr;
use_tree(uint64_t, sym_ptr);
typedef tree(uint64_t, sym_ptr) hll_syms_map_t;
use_hash_table(int, hll_syms_map_t);

static hash_table(int, hll_syms_map_t) hll_syms;


static uint64_t stack_hash(struct stack *stack) {
        uint64_t  hash;
        int       i;
        uint64_t  piece;

        hash = 2654435761ULL;

        for (i = 0; i < MAX_STACK_DEPTH; i += 1) {
                piece = (stack->addrs[i] >> 3);
                if (piece == 0) { break; }
                hash *= piece;
                if (hash == 0) {
                        hash = piece;
                }
        }
        
        return hash;
}

static uint64_t u64_id_hash(uint64_t val) { return val; }
static uint64_t addr_hash(uint64_t addr) { return addr >> 3; }
static uint64_t id_hash(int x) { return x; }

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

        if (hll_syms == NULL) {
                hll_syms = hash_table_make(int, hll_syms_map_t, id_hash);
        }

        if (blacklists == NULL) {
                blacklists = hash_table_make(int, blacklist_t, id_hash);
        }

        return 0;
}

static void free_hll_syms_map(hll_syms_map_t map) {
        tree_it(uint64_t, sym_ptr) it;

        tree_traverse(map, it) {
                free((char*)tree_it_val(it)->name);
                free(tree_it_val(it));
        }

        tree_free(map);
}

void deinit_syms_cache()
{
        int pid;
        hll_syms_map_t *val;
        blacklist_t *blacklistp;

        if (syms_cache == NULL) {
                return;
        }

        syms_cache__free(syms_cache);
        hash_table_traverse(hll_syms, pid, val) {
                (void)pid;
                free_hll_syms_map(*val);
        }
        hash_table_free(hll_syms);

        hash_table_traverse(blacklists, pid, blacklistp) {
                hash_table_free(*blacklistp);
        }
        hash_table_free(blacklists);
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
                        fprintf(stderr, "WARNING error opening %s\n", tmpfile);
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

static hll_syms_map_t reload_hll_syms(int pid) {
        hll_syms_map_t *lookup;

        lookup = hash_table_get_val(hll_syms, pid);
        if (lookup != NULL) {
                free_hll_syms_map(*lookup);
                hash_table_delete(hll_syms, pid);
        }

        return get_hll_syms(pid);
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

int is_blacklisted(int pid, uint64_t addr) {
        blacklist_t *blp;
        blacklist_t  bl;

        blp = hash_table_get_val(blacklists, pid);
        if (blp == NULL) {
                bl = hash_table_make(uint64_t, char, addr_hash);
                hash_table_insert(blacklists, pid, bl);
                return 0;
        }

        bl = *blp;
        return !!hash_table_get_val(bl, addr);
}

void blacklist(int pid, uint64_t addr) {
        blacklist_t *blp;
        blacklist_t  bl;

        blp = hash_table_get_val(blacklists, pid);
        if (blp == NULL) {
                bl = hash_table_make(uint64_t, char, addr_hash);
                hash_table_insert(blacklists, pid, bl);
                return;
        }

        bl = *blp;
        hash_table_insert(bl, addr, 1);
}

char *get_stack(struct stack *stack) {
        char **lookup;

        if (stacks == NULL) {
                return NULL;
        }
        
        lookup = hash_table_get_val(stacks, stack_hash(stack));
        if (!lookup) {
                return NULL;
        }
        return *lookup;
}

char *store_stack(int pid, int tid, struct stack *stack)
{
        uint64_t hash;
        const struct syms *syms;
        hll_syms_map_t hll_syms_map;
        const struct sym *sym;
        char tid_buf[64];
        int sfd, i, last_i;
        size_t len, cur_len, new_len;
        const char *to_copy;
        char *dso_name, should_free;
        unsigned long dso_offset;
        char *stack_str;
        char **lookup;

        stack_str = NULL;

        if (stacks == NULL) {
                stacks = hash_table_make(uint64_t, string, u64_id_hash);
        }
        
        hash = stack_hash(stack);
        
        lookup = hash_table_get_val(stacks, hash);
        if (lookup) {
                return *lookup;
        }

        if (pthread_rwlock_wrlock(&syms_cache_lock) != 0) {
                fprintf(stderr,
                        "Error grabbing the syms_cache_lock. Aborting.\n");
                exit(1);
        }

        if (pid == 0) {
                stack_str = strdup("[unknown]");
                goto insert;
        }

        sfd = bpf_map__fd(bpf_info.obj->maps.stackmap);
        if (sfd <= 0) {
                fprintf(stderr, "Failed to get stackmap.\n");
                stack_str = strdup("[unknown]");
                goto insert;
        }

        if (init_syms_cache() != 0) {
                stack_str = strdup("[unknown]");
                goto insert;
        }
        syms = syms_cache__get_syms(syms_cache, pid);
        if (!syms) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Failed to get syms for PID %" PRIu32
                                "\n",
                                pid);
                }
                stack_str = strdup("[unknown]");
                goto insert;
        }
        hll_syms_map = get_hll_syms(pid);


#if STACK_INCLUDE_TID
        snprintf(tid_buf, sizeof(tid_buf), "%u;", tid);
        stack_str = strdup(tid_buf);
#else
        (void)tid_buf;
#endif

        /* Start at the last nonzero IP */
        last_i = 0;
        for (i = 0; i < MAX_STACK_DEPTH && stack->addrs[i]; i++) {
                last_i = i;
        }

        for (i = last_i; i >= 0; i--) {
                should_free = 0;
                dso_name = NULL;
                sym = syms__map_addr_dso(syms, stack->addrs[i], &dso_name, &dso_offset);
                if (sym == NULL) {
                        sym = hll_sym(hll_syms_map, stack->addrs[i]);
                }
                if (sym == NULL) {
                        if (!is_blacklisted(pid, stack->addrs[i])) {
                                hll_syms_map = reload_hll_syms(pid);
                                sym = hll_sym(hll_syms_map, stack->addrs[i]);
                                if (sym == NULL) {
                                        blacklist(pid, stack->addrs[i]);
                                }
                        }
                }

                cur_len = 0;
                if (stack_str) {
                        cur_len = strlen(stack_str);
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
                                sprintf(tmp_str, "0x%llx", stack->addrs[i]);
                                to_copy = tmp_str;
                        }
                }
                len = strlen(to_copy);
                new_len = cur_len + len + 2;
                stack_str = realloc(stack_str, new_len);
                memset(stack_str + cur_len, 0, new_len - cur_len);
                strcpy(stack_str + cur_len, to_copy);
                (stack_str)[new_len - 2] = ';';
                if (should_free) {
                        free((void *)to_copy);
                }
        }

insert:

        hash_table_insert(stacks, hash, stack_str);

        if (pthread_rwlock_unlock(&syms_cache_lock) != 0) {
                fprintf(stderr,
                        "Error unlocking the syms_cache_lock. Aborting.\n");
                exit(1);
        }

        return stack_str;
}
