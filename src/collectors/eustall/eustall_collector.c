#include <stdlib.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <drm/i915_drm_prelim.h>

#include "iaprof.h"

#include "drm_helpers/drm_helpers.h"
#include "i915_helpers/i915_helpers.h"

#include "collectors/eustall/eustall_collector.h"
#include "collectors/bpf_i915/bpf_i915_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "printers/printer.h"

uint64_t uint64_t_hash(uint64_t i)
{
	return i;
}

uint64_t max_bit_value(uint64_t n)
{
	return ((n == 64) ? 0xFFFFFFFFFFFFFFFF :
			    ((((unsigned long long)1) << n) - 1));
}

uint64_t canonize(uint64_t address)
{
	return (uint64_t)(address << (64 - 48)) >> (64 - 48);
}

uint64_t decanonize(uint64_t address)
{
	return (address & max_bit_value(48));
}

int associate_sample(struct eustall_sample *sample, struct buffer_profile *gem,
		     uint64_t gpu_addr, uint64_t offset, uint16_t subslice,
		     unsigned long long time)
{
	struct offset_profile **found;
	struct offset_profile *profile;

	/* First, ensure that we've already initialized the shader-specific
     data structures */
	if (gem->has_stalls == 0) {
		gem->shader_profile.counts =
			hash_table_make(uint64_t, uint64_t, uint64_t_hash);
		if (!(gem->shader_profile.counts)) {
			fprintf(stderr,
				"WARNING: Failed to create a hash table.\n");
			return -1;
		}
		gem->has_stalls = 1;
	}

	if (verbose) {
		print_eustall(sample, gpu_addr, offset,
			      gem->vm_bind_info.handle, subslice, time);
	}

	/* Check if this offset has been seen yet */
	found = (struct offset_profile **)hash_table_get_val(
		gem->shader_profile.counts, offset);
	if (!found) {
		/* We have to allocate a struct of counts */
		profile = calloc(1, sizeof(struct offset_profile));
		hash_table_insert(gem->shader_profile.counts, offset,
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
	int i, n, num_not_found, num_found;
	char found, search_stale;
	uint64_t addr, start, end, offset, last_found_start, last_found_offset;
	struct eustall_sample sample;
	struct buffer_profile *gem, *last_found_gem;
	struct timespec spec;
	unsigned long long time;

	if (pthread_rwlock_rdlock(&buffer_profile_lock) != 0) {
		fprintf(stderr,
			"Failed to grab the buffer_profile_lock for reading.\n");
		return EUSTALL_STATUS_ERROR;
	}

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
		last_found_start = 0;
		last_found_offset = 0;
		last_found_gem = NULL;
		search_stale = 0; /* Look at stale buffers, too? */

                if (!iba) {
                        goto none_found;
                }

retry:
		for (n = 0; n < buffer_profile_used; n++) {
			gem = &buffer_profile_arr[n];
			start = gem->vm_bind_info.gpu_addr;
			end = start + gem->vm_bind_info.size;
                        
			if (gem->vm_bind_info.stale && (!search_stale)) {
				continue;
			}

			if ((addr < start) || (addr >= end)) {
				continue;
			}

			if ((addr - start) > MAX_BINARY_SIZE) {
                                if (debug) {
                                        fprintf(stderr, "WARNING: eustall gpu_addr=0x%lx", addr);
                                        fprintf(stderr, " lands in handle=%u,", gem->handle);
                                        fprintf(stderr, " which is bigger than MAX_BINARY_SIZE.\n");
                                }
			}

			offset = addr - start;

			if (debug) {
				printf("ip=0x%lx addr=0x%lx start=0x%lx offset=0x%lx gpu_addr=0x%llx iba=0x%lx\n",
				       (uint64_t)sample.ip, addr, start, offset,
				       gem->vm_bind_info.gpu_addr, iba);
			}
			found++;
			last_found_start = start;
			last_found_offset = offset;
			last_found_gem = gem;
			continue;
		}

none_found:
		/* Now that we've found 0+ matches, print or store them. */
		if (found == 0) {
			/* No matches found! */
			if (!search_stale) {
				/* If we haven't already retried for this stall, 
                                   search all buffers again but consider "stale" ones too. */
				if (debug) {
					printf("addr=0x%lx trying again\n",
					       addr);
				}
				search_stale = 1;
				goto retry;
			} else {
				/* We've tried twice, bail out */
				if (verbose) {
					print_eustall_drop(&sample, addr,
							   info.subslice, time);
				}
				num_not_found++;
			}
		} else if (found == 1) {
			associate_sample(&sample, last_found_gem, addr,
					 last_found_offset, info.subslice,
					 time);
			num_found++;
		} else if (found > 1) {
                        /* We'll have to just bail out */
			if (verbose) {
			        print_eustall_churn(&sample, addr,
				                    last_found_offset,
				                    info.subslice,
					            time);
			}
		}
	}

	if (debug && (num_found != 0)) {
		print_total_eustall(num_found, time);
	}

	if (pthread_rwlock_unlock(&buffer_profile_lock) != 0) {
		fprintf(stderr, "Failed to unlock the buffer_profile_lock.\n");
		return EUSTALL_STATUS_ERROR;
	}

	g_samples_matched += num_found;
	g_samples_unmatched += num_not_found;

        if (num_not_found) {
                if (debug) {
                        fprintf(stderr, "WARNING: Dropping %d eustall samples.\n", num_not_found);
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
	ioctl(fd, I915_PERF_IOCTL_ENABLE, NULL, 0);

        /* Add the fd to the epoll_fd */
        eustall_info.perf_fd = fd;
        add_to_epoll_fd(fd);

cleanup:
	free(properties);

	return 0;
}
