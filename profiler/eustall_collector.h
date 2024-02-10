#include <drm/i915_drm_prelim.h>
#include <sys/ioctl.h>

#include "gpu_kernel_decoder.h"
#include "gem_collector.h"
#include "shader_decoder.h"

uint64_t uint64_t_hash(uint64_t i) { return i; }

uint64_t max_bit_value(uint64_t n) {
  return ((n == 64) ? 0xFFFFFFFFFFFFFFFF
                    : ((((unsigned long long) 1) << n) - 1));
}

uint64_t canonize(uint64_t address) {
  return (uint64_t) (address << (64 - 48)) >> (64 - 48);
}

uint64_t decanonize(uint64_t address) {
  return (address & max_bit_value(48));
}


int associate_sample(struct eustall_sample *sample, GEM_ARR_TYPE *gem,
                     uint64_t gpu_addr, uint64_t offset, uint16_t subslice,
                     unsigned long long time) {
  struct offset_profile **found;
  struct offset_profile *profile;
  
  /* First, ensure that we've already initialized the shader-specific
     data structures */
  if(gem->has_stalls == 0) {
    gem->shader_profile.counts = hash_table_make(uint64_t, uint64_t, uint64_t_hash);
    if(!(gem->shader_profile.counts)) {
      fprintf(stderr, "WARNING: Failed to create a hash table.\n");
      return -1;
    }
    gem->has_stalls = 1;
  }
  
  if(debug) {
    print_eustall(sample, gpu_addr, offset, gem->mapping_info.handle, subslice, time);
  }
  
  /* Check if this offset has been seen yet */
  found = (struct offset_profile **) hash_table_get_val(gem->shader_profile.counts, offset);
  if(!found) {
    /* We have to allocate a struct of counts */
    profile = calloc(1, sizeof(struct offset_profile));
    hash_table_insert(gem->shader_profile.counts, offset, (uint64_t) profile);
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

int handle_eustall_samples(uint8_t *perf_buf, int len) {
  struct prelim_drm_i915_stall_cntr_info info;
  int i, n, num_not_found;
  char found;
  uint64_t addr, start, end, offset, last_found_start;
  struct eustall_sample sample;
  GEM_ARR_TYPE *gem;
  struct timespec spec;
  unsigned long long time;
  
  if(pthread_rwlock_rdlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to grab the gem_lock for reading.\n");
    return -1;
  }
  
  /* Get the timestamp */
  clock_gettime(CLOCK_MONOTONIC, &spec);
  time = spec.tv_sec * 1000000000UL + spec.tv_nsec;
  
  num_not_found = 0;
  for(i = 0; i < len; i += 64) {
    
    memcpy(&sample, perf_buf + i, sizeof(struct eustall_sample));
    memcpy(&info, perf_buf + i + 48, sizeof(info));
    addr = ((uint64_t) sample.ip) << 3;
    
    /* Look up this sample by the GPU address (sample.ip). If we find
       multiple matches, that means that multiple contexts are using
       the same virtual address, and there's no way to determine which
       one the EU stall is associated with */
    found = 0;
    last_found_start = 0;
    for(n = 0; n < gem_arr_used; n++) {
      gem = &gem_arr[n];
      start = gem->vm_bind_info.gpu_addr & 0xffffffff;
      end = start + gem->vm_bind_info.size;
      
      if((addr >= start) && (addr < end)) {
        offset = addr - start;
        if(found && (last_found_start != start)) {
          /* If we found multiple buffers, not starting at the same
             address, that could have caused this EU stall, just bail out. */
          found = 0;
          break;
        }
        found++;
        last_found_start = start;
        continue;
      }
    }
    if(found == 0) {
      print_eustall_drop(&sample, addr, info.subslice, time);
      num_not_found++;
    } else if(found == 1) {
      associate_sample(&sample, gem, addr, offset, info.subslice, time);
    } else if(found > 1) {
      /* Multiple buffers could "claim" this EU stall, but we've
         confirmed that they all start with the same address. Print
         what information we know: the offset and subslice. */
      print_eustall_churn(&sample, addr, offset, info.subslice, time);
    }
  }
  
  if(pthread_rwlock_unlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to unlock the gem_lock.\n");
    return -1;
  }
  
  return num_not_found;
}

int configure_eustall(int **perf_fd, int *num_perf_fd) {
  struct device_info *devinfo;
  struct i915_engine_class_instance *engine_class;
  int i, fd;
  
  /* Grab the i915 driver file descriptor */
  devinfo = open_first_driver();
  if(!devinfo) {
    fprintf(stderr, "Failed to open any drivers. Aborting.\n");
    exit(1);
  }
  
  /* Get information about the device */
  if(get_drm_device_info(devinfo) != 0) {
    fprintf(stderr, "Failed to get device info. Aborting.\n");
    exit(1);
  }
  
  if(i915_query_engines(devinfo->fd, &(devinfo->engine_info)) != 0) {
    fprintf(stderr, "Failed to get engine info. Aborting.\n");
    exit(1);
  }
  
  uint64_t properties[] = {
		PRELIM_DRM_I915_EU_STALL_PROP_BUF_SZ, p_size,
		PRELIM_DRM_I915_EU_STALL_PROP_SAMPLE_RATE, p_rate,
		PRELIM_DRM_I915_EU_STALL_PROP_POLL_PERIOD, p_poll_period,
		PRELIM_DRM_I915_EU_STALL_PROP_EVENT_REPORT_COUNT, p_event_count,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_CLASS, 4,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE, 0,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE, 1,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE, 2,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE, 3,
  };
  
	struct drm_i915_perf_open_param param = {
		.flags = I915_PERF_FLAG_FD_CLOEXEC |
			 PRELIM_I915_PERF_FLAG_FD_EU_STALL |
			 I915_PERF_FLAG_DISABLED,
		.num_properties = sizeof(properties) / 16,
    .properties_ptr = (unsigned long long) properties,
	};
  
/*   i = 0; */
/*   for_each_engine(devinfo->engine_info, engine_class) { */
/*     if(engine_class->engine_class == PRELIM_I915_ENGINE_CLASS_COMPUTE) { */
      
  /* Open the fd */
  fd = ioctl_do(devinfo->fd, DRM_IOCTL_I915_PERF_OPEN, &param);
  if(fd < 0) {
    fprintf(stderr, "Failed to open the perf file descriptor.\n");
    return -1;
  }
  
  /* Enable the fd */
  ioctl(fd, I915_PERF_IOCTL_ENABLE, NULL, 0);
  
  /* Store the fd */
  *perf_fd = realloc(*perf_fd, sizeof(int) * (i + 1));
  (*perf_fd)[i] = fd;
  (*num_perf_fd)++;
  
  /* Free up the device info */
  free_driver(devinfo);
  
  return 0;
}
