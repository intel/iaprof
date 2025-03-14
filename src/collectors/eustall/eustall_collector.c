#include <stdlib.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>

#include "iaprof.h"
#include "drm_helpers/drm_helpers.h"
#include "stores/gpu_kernel_stalls.h"
#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf/bpf_collector.h"
#include "gpu_parsers/shader_decoder.h"
#include "printers/debug/debug_printer.h"

/* Driver-specific stuff */
#if GPU_DRIVER == GPU_DRIVER_xe
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>
#include <uapi/drm/xe_drm_eudebug.h>
#include "driver_helpers/xe_helpers.h"
#elif GPU_DRIVER == GPU_DRIVER_i915
#include <drm/i915_drm_prelim.h>
#include "driver_helpers/i915_helpers.h"
#endif

pthread_cond_t eustall_deferred_attrib_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t eustall_deferred_attrib_cond_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t eustall_waitlist_mtx = PTHREAD_MUTEX_INITIALIZER;

array_t *eustall_waitlist;
static array_t eustall_waitlist_a;
static array_t eustall_waitlist_b;

uint64_t uint64_t_hash(uint64_t i)
{
        return i;
}

uint64_t num_stalls_in_sample(struct eustall_sample *sample)
{
        uint64_t total;

        total = 0;
        total += sample->active;
        total += sample->other;
        total += sample->control;
        total += sample->pipestall;
        total += sample->send;
        total += sample->dist_acc;
        total += sample->sbid;
        total += sample->sync;
        total += sample->inst_fetch;
#if GPU_DRIVER == GPU_DRIVER_xe
        total += sample->tdr;
#endif

        return total;
}

int associate_sample(struct eustall_sample *sample, uint64_t file, uint32_t vm_id,
                     uint64_t gpu_addr, uint64_t offset,
                     unsigned long long time)
{
        struct offset_profile *found;
        struct offset_profile profile;
        struct vm_profile *vm;
        struct shader_binding *shader;

        vm = acquire_vm_profile(file, vm_id);

        if (!vm) {
                debug_printf("associate_sample didn't find vm_id=%u\n", vm_id);
                return -1;
        }

        shader = get_shader(vm, gpu_addr);

        if (!shader) {
                debug_printf("associate_sample didn't find vm_id=%u gpu_addr=0x%lx\n",
                     vm_id, gpu_addr);
                release_vm_profile(vm);
                return -1;
        }

        /* Make sure we're initialized */
        if (shader->stall_counts == NULL) {
                shader->stall_counts =
                        hash_table_make(uint64_t, offset_profile_struct, uint64_t_hash);
        }

        /* Check if this offset has been seen yet */
        found = hash_table_get_val(shader->stall_counts, offset);
        if (!found) {
                /* We have to allocate a struct of counts */
                memset(&profile, 0, sizeof(profile));
                hash_table_insert(shader->stall_counts, offset, profile);
                found = hash_table_get_val(shader->stall_counts, offset);
        }

        found->active     += sample->active;
        found->other      += sample->other;
        found->control    += sample->control;
        found->pipestall  += sample->pipestall;
        found->send       += sample->send;
        found->dist_acc   += sample->dist_acc;
        found->sbid       += sample->sbid;
        found->sync       += sample->sync;
        found->inst_fetch += sample->inst_fetch;
#if GPU_DRIVER == GPU_DRIVER_xe
        found->tdr        += sample->tdr;
#endif

        release_vm_profile(vm);
        return 0;
}

enum {
        EUSTALL_SAMPLE_DEFERRED                 = (1 << 0),
        EUSTALL_SAMPLE_SHADER_TYPE_NOT_REQUIRED = (1 << 1),
};

static int handle_eustall_sample(struct eustall_sample *sample, unsigned long long time, int flags) {
        int found;
        uint64_t addr;
        uint64_t start;
        uint64_t offset;
        uint64_t low_offset_shader_addr;
        uint64_t low_offset_offset;
        uint32_t low_offset_vm_id;
        uint64_t low_offset_file;
        uint64_t low_offset_addr;
        
        struct deferred_eustall deferred;
        struct vm_profile *vm;
        struct shader_binding *shader;

        addr = (((uint64_t)sample->ip) << 3) + iba;

        /* Look up this sample by the GPU address (sample->ip). If we find
                multiple matches, that means that multiple contexts are using
                the same virtual address, and there's no way to determine which
                one the EU stall is associated with */
        found = 0;

        low_offset_shader_addr = 0;
        low_offset_offset = (uint64_t)-1;
        low_offset_vm_id = 0;
        low_offset_file = 0;
        low_offset_addr = 0;

        if (!iba) {
/*                 goto none_found; */
        }
        
        FOR_VM(vm, {

                shader = get_containing_shader(vm, addr);
                if (shader == NULL) {
                        goto next;
                }

                if (!(shader->pid)) {
                        goto next;
                }

                if (!(flags & EUSTALL_SAMPLE_SHADER_TYPE_NOT_REQUIRED)) {
                        if ((shader->type != SHADER_TYPE_SHADER)
                        &&  (shader->type != SHADER_TYPE_DEBUG_AREA)
                        &&  (shader->type != SHADER_TYPE_SYSTEM_ROUTINE)) {

                                goto next;
                        }
                }

                start = shader->gpu_addr;
                offset = addr - start;

                found++;

                if (offset < low_offset_offset) {
                        low_offset_shader_addr = start;
                        low_offset_offset = offset;
                        low_offset_vm_id = vm->vm_id;
                        low_offset_file = vm->file;
                        low_offset_addr = addr;
                }

/* Jump here instead of continue so that the macro invokes the unlock functions. */
next:;
        });

/* none_found: */
        /* Now that we've found 0+ matches, print or store them. */
        if (found == 0) {
                if (!(flags & EUSTALL_SAMPLE_DEFERRED)) {
                        deferred.sample    = *sample;
                        deferred.satisfied = 0;

                        pthread_mutex_lock(&eustall_waitlist_mtx);
                        array_push(*eustall_waitlist, deferred);
                        pthread_mutex_unlock(&eustall_waitlist_mtx);

                        eustall_info.deferred += num_stalls_in_sample(sample);
                }
        } else if (found == 1) {
          
                associate_sample(sample, low_offset_file, low_offset_vm_id,
                                 low_offset_shader_addr, low_offset_offset,
                                 time);
                eustall_info.matched += num_stalls_in_sample(sample);
        } else if (found > 1) {
        
                /* We have to guess. Choose the last one that we've found. */
                associate_sample(sample, low_offset_file, low_offset_vm_id,
                                 low_offset_shader_addr, low_offset_offset,
                                 time);
                eustall_info.guessed += num_stalls_in_sample(sample);
        }
        
        if (found) {
                debug_printf("file=0x%lx vm_id=%u shader_addr=0x%lx offset=0x%lx addr=0x%lx\n", low_offset_file, low_offset_vm_id,
                            low_offset_shader_addr, low_offset_offset, low_offset_addr);
        }
        
        return found > 0;
}

#if GPU_DRIVER == GPU_DRIVER_xe
int handle_eustall_samples(void *perf_buf, int len, struct device_info *devinfo)
{
        struct timespec spec;
        unsigned long long time;
        int i;
        struct eustall_sample *sample;

        /* Get the timestamp */
        clock_gettime(CLOCK_MONOTONIC, &spec);
        time = spec.tv_sec * 1000000000UL + spec.tv_nsec;

        for (i = 0; i < len; i += devinfo->record_size) {
                sample = perf_buf + i;

                /* We're going to read from the end of the header until the end of these records */
                if (sample > ((struct eustall_sample *)(perf_buf + len))) {
                        /* Reading all of these samples would put us past the end of the buffer that we read */
                        debug_printf("EU stall reading would put us back the end of the buffer.\n");
                        break;
                }

                handle_eustall_sample(sample, time, 0);
        }

        return EUSTALL_STATUS_OK;
}
#elif GPU_DRIVER == GPU_DRIVER_i915
int handle_eustall_samples(void *perf_buf, int len, struct device_info *devinfo)
{
        struct timespec spec;
        unsigned long long time;
        int i;
        struct eustall_sample *sample;

        /* Get the timestamp */
        clock_gettime(CLOCK_MONOTONIC, &spec);
        time = spec.tv_sec * 1000000000UL + spec.tv_nsec;

        for (i = 0; i < len; i += 64) {
                sample = perf_buf + i;
                handle_eustall_sample(sample, time, 0);
        }

        return EUSTALL_STATUS_OK;
}
#endif

void handle_deferred_eustalls() {
        array_t *working;
        struct deferred_eustall *stall;
        int n_satisfied, n_waitlist;

        pthread_mutex_lock(&eustall_waitlist_mtx);

        if (array_len(*eustall_waitlist) == 0) {
                pthread_mutex_unlock(&eustall_waitlist_mtx);
                return;
        }

        /* Double buffer so that more eustalls can be added to the
         * wait list while we're working on the current set. */
        working = eustall_waitlist;
        eustall_waitlist = working == &eustall_waitlist_a
                                ? &eustall_waitlist_b
                                : &eustall_waitlist_a;
        array_clear(*eustall_waitlist);
        pthread_mutex_unlock(&eustall_waitlist_mtx);

        n_waitlist = array_len(*working);
        if (n_waitlist) {
                debug_printf("Working on %d deferred eustall samples.\n", n_waitlist);
        }

        /* Try to satisfy each pending eustall. */
        n_satisfied = 0;
        array_traverse(*working, stall) {
                stall->satisfied = handle_eustall_sample(&stall->sample, stall->time, EUSTALL_SAMPLE_DEFERRED);
                n_satisfied += !!stall->satisfied;
        }

        if (n_satisfied) {
                debug_printf("Satisfied %d/%d deferred eustall samples.\n", n_satisfied, n_waitlist);
        }

        /* Put any yet-unsatisfied eustalls back on the current waitlist. */
        pthread_mutex_lock(&eustall_waitlist_mtx);
        array_traverse(*working, stall) {
                if (!stall->satisfied) {
                        array_push(*eustall_waitlist, *stall);
                }
        }
        pthread_mutex_unlock(&eustall_waitlist_mtx);
}

void init_eustall_waitlist() {
        eustall_waitlist_a = array_make(struct deferred_eustall);
        eustall_waitlist_b = array_make(struct deferred_eustall);
        eustall_waitlist   = &eustall_waitlist_a;
}

int init_eustall(device_info *devinfo)
{
        int fd;

#if GPU_DRIVER == GPU_DRIVER_xe
        fd = xe_init_eustall(devinfo);
#elif GPU_DRIVER == GPU_DRIVER_i915
        fd = i915_init_eustall(devinfo);
#endif

        if (fd <= 0) {
                fprintf(stderr, "Failed to initialize eustalls. Aborting.\n");
                return -1;
        }

        /* Add the fd to the epoll_fd */
        eustall_info.perf_fd = fd;

        return 0;
}

void wakeup_eustall_deferred_attrib_thread() {
        pthread_mutex_lock(&eustall_deferred_attrib_cond_mtx);
        pthread_cond_signal(&eustall_deferred_attrib_cond);
        pthread_mutex_unlock(&eustall_deferred_attrib_cond_mtx);
}

void handle_remaining_eustalls() {
        struct deferred_eustall *it;

        pthread_mutex_lock(&eustall_waitlist_mtx);
        array_traverse(*eustall_waitlist, it) {
                handle_eustall_sample(&it->sample, it->time, EUSTALL_SAMPLE_DEFERRED | EUSTALL_SAMPLE_SHADER_TYPE_NOT_REQUIRED);

                eustall_info.unmatched += num_stalls_in_sample(&it->sample);
        }
        pthread_mutex_unlock(&eustall_waitlist_mtx);
}
