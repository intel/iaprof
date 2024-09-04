#include <stdlib.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <drm/i915_drm_prelim.h>

#include "iaprof.h"

#include "drm_helpers/drm_helpers.h"
#include "i915_helpers/i915_helpers.h"

#include "stores/buffer_profile.h"

#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "printers/printer.h"

pthread_cond_t eustall_deferred_attrib_cond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t eustall_deferred_attrib_cond_mtx = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t eustall_waitlist_mtx = PTHREAD_MUTEX_INITIALIZER;

array_t *eustall_waitlist;
static array_t eustall_waitlist_a;
static array_t eustall_waitlist_b;

struct deferred_eustall {
        unsigned long long time;
        struct eustall_sample sample;
        struct prelim_drm_i915_stall_cntr_info info;
        char satisfied;
};

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

        return total;
}

int associate_sample(struct eustall_sample *sample, uint32_t vm_id,
                     uint64_t gpu_addr, uint64_t offset,
                     uint16_t subslice, unsigned long long time)
{
        struct offset_profile **found;
        struct offset_profile *profile;
        struct vm_profile *vm;
        struct buffer_binding *bind;

        vm = acquire_vm_profile(vm_id);

        if (!vm) {
                fprintf(stderr, "WARNING: associate_sample didn't find vm_id=%u\n",
                        vm_id);
                return -1;
        }

        bind = get_containing_binding(vm, gpu_addr);

        if (!bind) {
                fprintf(stderr, "WARNING: associate_sample didn't find vm_id=%u gpu_addr=0x%lx\n",
                        vm_id, gpu_addr);
                release_vm_profile(vm);
                return -1;
        }

        /* Make sure we're initialized */
        if (bind->stall_counts == NULL) {
                bind->stall_counts =
                        hash_table_make(uint64_t, uint64_t, uint64_t_hash);
        }

        if (verbose) {
                print_eustall(sample, gpu_addr, offset, bind->handle, subslice,
                              time);
        }

        /* Check if this offset has been seen yet */
        found = (struct offset_profile **)hash_table_get_val(
                bind->stall_counts, offset);
        if (!found) {
                /* We have to allocate a struct of counts */
                profile = calloc(1, sizeof(struct offset_profile));
                hash_table_insert(bind->stall_counts, offset,
                                  (uint64_t)profile);
                found = &profile;
        }
        (*found)->active += sample->active;
        (*found)->other += sample->other;
        (*found)->control += sample->control;
        (*found)->pipestall += sample->pipestall;
        (*found)->send += sample->send;
        (*found)->dist_acc += sample->dist_acc;
        (*found)->sbid += sample->sbid;
        (*found)->sync += sample->sync;
        (*found)->inst_fetch += sample->inst_fetch;

        release_vm_profile(vm);
        return 0;
}

static int handle_eustall_sample(struct eustall_sample *sample, struct prelim_drm_i915_stall_cntr_info *info, unsigned long long time, int is_deferred) {
        int found;
        uint64_t addr, start, end, offset, first_found_offset;
        uint32_t first_found_vm_id;
        struct deferred_eustall deferred;
        struct vm_profile *vm;
        struct buffer_binding *bind;

        addr = (((uint64_t)sample->ip) << 3) + iba;

        /* Look up this sample by the GPU address (sample->ip). If we find
                multiple matches, that means that multiple contexts are using
                the same virtual address, and there's no way to determine which
                one the EU stall is associated with */
        found = 0;

        first_found_offset = 0;
        first_found_vm_id = 0;

        if (!iba) {
                goto none_found;
        }

        FOR_VM(vm, {

                bind = get_containing_binding(vm, addr);

                if (bind == NULL) {
                        goto next;
                }

                if (!(bind->pid)) {
                        goto next;
                }

                if ((bind->type != BUFFER_TYPE_SHADER) &&
                    (bind->type != BUFFER_TYPE_DEBUG_AREA)) {
                        goto next;
                }

                start = bind->gpu_addr;
                end = start + bind->bind_size;
                offset = addr - start;

                debug_printf("addr=0x%lx start=0x%lx end=0x%lx offset=0x%lx handle=%u vm_id=%u gpu_addr=0x%lx iba=0x%lx\n",
                        addr, start, end, offset,
                        bind->handle, bind->vm_id,
                        bind->gpu_addr, iba);

                if ((addr - start) > MAX_BINARY_SIZE) {
                        if (debug) {
                                fprintf(stderr,
                                        "WARNING: eustall gpu_addr=0x%lx",
                                        addr);
                                fprintf(stderr, " lands in handle=%u,",
                                        bind->handle);
                                fprintf(stderr,
                                        " which is bigger than MAX_BINARY_SIZE.\n");
                        }
                }

                found++;

                if (found == 1) {
                        first_found_offset = offset;
                        first_found_vm_id = vm->vm_id;
                }

/* Jump here instead of continue so that the macro invokes the unlock functions. */
next:;
        });

none_found:
        /* Now that we've found 0+ matches, print or store them. */
        if (found == 0) {
                if (!is_deferred) {
                        deferred.sample    = *sample;
                        deferred.info      = *info;
                        deferred.satisfied = 0;

                        pthread_mutex_lock(&eustall_waitlist_mtx);
                        array_push(*eustall_waitlist, deferred);
                        pthread_mutex_unlock(&eustall_waitlist_mtx);

                        if (verbose) {
                                print_eustall_defer(sample, addr, info->subslice,
                                                    time);
                        }
                        eustall_info.deferred += num_stalls_in_sample(sample);
                }
        } else if (found == 1) {
                associate_sample(sample, first_found_vm_id,
                                 addr, first_found_offset,
                                 info->subslice, time);
                eustall_info.matched += num_stalls_in_sample(sample);
        } else if (found > 1) {
                /* We have to guess. Choose the last one that we've found. */
                if (verbose) {
                        print_eustall_churn(sample, addr,
                                            first_found_offset,
                                            info->subslice, time);
                }

                associate_sample(sample, first_found_vm_id,
                                 addr, first_found_offset,
                                 info->subslice, time);
                eustall_info.guessed += num_stalls_in_sample(sample);
        }

        return found > 0;
}

int handle_eustall_samples(void *perf_buf, int len)
{
        struct timespec spec;
        unsigned long long time;
        int i;
        struct eustall_sample *sample;
        struct prelim_drm_i915_stall_cntr_info *info;


        /* Get the timestamp */
        clock_gettime(CLOCK_MONOTONIC, &spec);
        time = spec.tv_sec * 1000000000UL + spec.tv_nsec;

        for (i = 0; i < len; i += 64) {
                sample = perf_buf + i;
                info   = perf_buf + i + 48;

                handle_eustall_sample(sample, info, time, /* is_deferred = */ 0);
        }

        return EUSTALL_STATUS_OK;
}

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
                stall->satisfied = handle_eustall_sample(&stall->sample, &stall->info, stall->time, 1);
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
        struct i915_engine_class_instance *engine_class;
        int i, fd, found, retval;
        uint64_t *properties;
        size_t properties_size;

        i = 0;
        properties_size = sizeof(uint64_t) * 5 * 2;
        properties = malloc(properties_size);

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_BUF_SZ;
        properties[i++] = DEFAULT_DSS_BUF_SIZE;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_SAMPLE_RATE;
        properties[i++] = DEFAULT_SAMPLE_RATE;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_POLL_PERIOD;
        properties[i++] = DEFAULT_POLL_PERIOD_NS;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_EVENT_REPORT_COUNT;
        properties[i++] = DEFAULT_EVENT_COUNT;

        properties[i++] = PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_CLASS;
        properties[i++] = 4;

        found = 0;
        for_each_engine(devinfo->engine_info, engine_class)
        {
                if (engine_class->engine_class ==
                    PRELIM_I915_ENGINE_CLASS_COMPUTE) {
                        properties_size += (sizeof(uint64_t) * 2);
                        properties = realloc(properties, properties_size);
                        properties[i++] =
                                PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE;
                        properties[i++] = engine_class->engine_instance;
                        found++;
                }
        }
        if (found == 0) {
                fprintf(stderr,
                        "WARNING: Didn't find any PRELIM_I915_ENGINE_CLASS_COMPUTE engines.\n");
                return -1;
        }

        struct drm_i915_perf_open_param param = {
                .flags = I915_PERF_FLAG_FD_CLOEXEC |
                         PRELIM_I915_PERF_FLAG_FD_EU_STALL |
                         I915_PERF_FLAG_DISABLED,
                .num_properties = properties_size / (sizeof(uint64_t) * 2),
                .properties_ptr = (unsigned long long)properties,
        };

        /* Open the fd */
        fd = ioctl_do(devinfo->fd, DRM_IOCTL_I915_PERF_OPEN, &param);
        if (fd < 0) {
                fprintf(stderr, "Failed to open the perf file descriptor.\n");
                return -1;
        }

        /* Enable the fd */
        retval = ioctl(fd, I915_PERF_IOCTL_ENABLE, NULL, 0);
        if (retval < 0) {
		        fprintf(stderr, "Failed to enable the perf file descriptor.\n");
		        return -1;
        }

        /* Add the fd to the epoll_fd */
        eustall_info.perf_fd = fd;

        free(properties);

        return 0;
}

void wakeup_eustall_deferred_attrib_thread() {
        pthread_mutex_lock(&eustall_deferred_attrib_cond_mtx);
        pthread_cond_signal(&eustall_deferred_attrib_cond);
        pthread_mutex_unlock(&eustall_deferred_attrib_cond_mtx);
}

void handle_remaining_eustalls() {
        struct timespec          spec;
        unsigned long long       time;
        struct deferred_eustall *it;
        uint64_t                 addr;

        /* Get the timestamp */
        clock_gettime(CLOCK_MONOTONIC, &spec);
        time = spec.tv_sec * 1000000000UL + spec.tv_nsec;

        pthread_mutex_lock(&eustall_waitlist_mtx);
        array_traverse(*eustall_waitlist, it) {
                addr = (((uint64_t)it->sample.ip) << 3) + iba;
                print_eustall_drop(&it->sample, addr, it->info.subslice, time);
                eustall_info.unmatched += num_stalls_in_sample(&it->sample);
        }
        pthread_mutex_unlock(&eustall_waitlist_mtx);
}
