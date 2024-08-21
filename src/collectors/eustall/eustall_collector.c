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

int associate_sample(struct eustall_sample *sample, struct buffer_profile *gem,
                     uint64_t gpu_addr, uint64_t offset,
                     uint16_t subslice, unsigned long long time)
{
        struct offset_profile **found;
        struct offset_profile *profile;

        /* Make sure we're initialized */
        if (gem->stall_counts == NULL) {
                gem->stall_counts =
                        hash_table_make(uint64_t, uint64_t, uint64_t_hash);
        }

        if (verbose) {
                print_eustall(sample, gpu_addr, offset, gem->handle, subslice,
                              time);
        }

        /* Check if this offset has been seen yet */
        found = (struct offset_profile **)hash_table_get_val(
                gem->stall_counts, offset);
        if (!found) {
                /* We have to allocate a struct of counts */
                profile = calloc(1, sizeof(struct offset_profile));
                hash_table_insert(gem->stall_counts, offset,
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

        return 0;
}

int handle_eustall_samples(uint8_t *perf_buf, int len)
{
        struct prelim_drm_i915_stall_cntr_info info;
        int i, num_not_found, num_found;
        char found;
        uint64_t addr, start, end, offset, first_found_offset;
        struct eustall_sample sample;
        struct vm_profile *vm;
        struct buffer_profile *gem, *first_found_gem;

        struct timespec spec;
        unsigned long long time;

        /* Get the timestamp */
        clock_gettime(CLOCK_MONOTONIC, &spec);
        time = spec.tv_sec * 1000000000UL + spec.tv_nsec;

        num_not_found = 0;
        num_found = 0;
        for (i = 0; i < len; i += 64) {
                memcpy(&sample, perf_buf + i, sizeof(struct eustall_sample));
                memcpy(&info, perf_buf + i + 48, sizeof(info));
                addr = (((uint64_t)sample.ip) << 3) + iba;

                /* Look up this sample by the GPU address (sample.ip). If we find
                   multiple matches, that means that multiple contexts are using
                   the same virtual address, and there's no way to determine which
                   one the EU stall is associated with */
                found = 0;

                first_found_offset = 0;
                first_found_gem = NULL;

                if (!iba) {
                        goto none_found;
                }

                FOR_VM_PROFILE(vm, {
                        if (vm->active == 0) {
                                debug_printf("  inactive!\n");
                                goto next;
                        }

                        gem = get_containing_buffer_profile(vm, addr);
                        if (gem == NULL) {
                                goto next;
                        }

                        start = gem->gpu_addr;
                        end = start + gem->bind_size;
                        offset = addr - start;

                        debug_printf("addr=0x%lx start=0x%lx end=0x%lx offset=0x%lx handle=%u vm_id=%u gpu_addr=0x%lx iba=0x%lx\n",
                                addr, start, end, offset,
                                gem->handle, gem->vm_id,
                                gem->gpu_addr, iba);

                        if (!(gem->pid)) {
                                debug_printf("  no exec_info!\n");
                                goto next;
                        }

                        if ((addr - start) > MAX_BINARY_SIZE) {
                                if (debug) {
                                        fprintf(stderr,
                                                "WARNING: eustall gpu_addr=0x%lx",
                                                addr);
                                        fprintf(stderr, " lands in handle=%u,",
                                                gem->handle);
                                        fprintf(stderr,
                                                " which is bigger than MAX_BINARY_SIZE.\n");
                                }
                        }

                        found++;

                        if (found == 1) {
                                first_found_offset = offset;
                                first_found_gem = gem;
                        }

/* Jump here instead of continue so that the macro invokes the unlock functions. */
next:;
                });

none_found:
                /* Now that we've found 0+ matches, print or store them. */
                if (found == 0) {
                        if (verbose) {
                                print_eustall_drop(&sample, addr, info.subslice,
                                                   time);
                        }
                        eustall_info.unmatched += num_stalls_in_sample(&sample);
                } else if (found == 1) {
                        associate_sample(&sample, first_found_gem,
                                         addr,
                                         first_found_offset, info.subslice,
                                         time);
                        eustall_info.matched += num_stalls_in_sample(&sample);
                } else if (found > 1) {
                        /* We have to guess. Choose the last one that we've found. */
                        if (verbose) {
                                print_eustall_churn(&sample, addr,
                                                    first_found_offset,
                                                    info.subslice, time);
                        }

                        associate_sample(&sample, first_found_gem,
                                         addr,
                                         first_found_offset, info.subslice,
                                         time);
                        eustall_info.guessed += num_stalls_in_sample(&sample);
                }
        }

        if (debug && (num_found != 0)) {
                print_total_eustall(num_found, time);
        }

        if (num_not_found) {
                if (debug) {
                        fprintf(stderr,
                                "WARNING: Dropping %d eustall samples.\n",
                                num_not_found);
                }
                return EUSTALL_STATUS_NOTFOUND;
        }
        return EUSTALL_STATUS_OK;
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
