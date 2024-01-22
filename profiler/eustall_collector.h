#include <drm/i915_drm_prelim.h>
#include <sys/ioctl.h>

#include "gpu_kernel_decoder.h"
#include "gem_collector.h"
#include "shader_decoder.h"

/** 101 bits
  * Bits    Field
  * 0  to 28  IP (addr)
  * 29 to 36  active count
  * 37 to 44  other count
  * 45 to 52  control count
  * 53 to 60  pipestall count
  * 61 to 68  send count
  * 69 to 76  dist_acc count
  * 77 to 84  sbid count
  * 85 to 92  sync count
  * 93 to 100  inst_fetch count
*/
struct __attribute__ ((__packed__)) eustall_sample {
  unsigned int ip : 29;
  unsigned short active : 8;
  unsigned short other : 8;
  unsigned short control : 8;
  unsigned short pipestall : 8;
  unsigned short send : 8;
  unsigned short dist_acc : 8;
  unsigned short sbid : 8;
  unsigned short sync : 8;
  unsigned short inst_fetch : 8;
};

uint64_t uint64_t_hash(uint64_t i) { return i; }

int associate_sample(struct eustall_sample *sample, GEM_ARR_TYPE *gem, uint64_t offset) {
  struct offset_profile **found;
  struct offset_profile *profile;
  iga_context_t *ctx;
  
  /* First, ensure that we've already initialized the shader-specific
     data structures */
  if(gem->is_shader == 0) {
    if((!gem->buff_sz) || (!gem->buff)) {
      return -1;
    }
    
    printf("associate_sample buff=0x%llx buff_sz=%llu size=%llu\n", (unsigned long long) gem->buff, (unsigned long long) gem->buff_sz, gem->kinfo.size);
    fflush(stdout);
    
    gem->shader_profile.counts = hash_table_make(uint64_t, uint64_t, uint64_t_hash);
    if(!(gem->shader_profile.counts)) {
      fprintf(stderr, "WARNING: Failed to create a hash table.\n");
      return -1;
    }
    
    /* TODO: only initialize per context */
    ctx = iga_init();
    iga_disassemble_shader(ctx, gem->buff, gem->kinfo.size);
    
    dump_buffer(gem->buff, gem->buff_sz, gem->kinfo.handle);
    
    gem->is_shader = 1;
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

void handle_eustall_samples(uint8_t *perf_buf, int len) {
  struct prelim_drm_i915_stall_cntr_info info;
  int i, n;
  uint64_t addr, start, end, offset;
  struct eustall_sample sample;
  GEM_ARR_TYPE *gem;
  
  if(pthread_rwlock_rdlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to grab the gem_lock for reading.\n");
    return;
  }
  
  for(i = 0; i < len; i += 64) {
    
    memcpy(&sample, perf_buf + i, sizeof(struct eustall_sample));
    memcpy(&info, perf_buf + i + 48, sizeof(info));
    addr = ((uint64_t) sample.ip) << 3;
    
    for(n = 0; n < gem_arr_used; n++) {
      gem = &gem_arr[n];
      start = gem->kinfo.gpu_addr & 0xffffffff;
      end = start + gem->kinfo.size;
      if((addr >= start) && (addr < end)) {
        offset = ((uint64_t) sample.ip) - (start >> 3);
        printf("associate_sample start=0x%lx start_shift=0x%lx sample.ip=0x%lx offset=0x%lx\n", start, start >> 3, (uint64_t) sample.ip, offset);
        associate_sample(&sample, gem, offset);
        break;
      }
    }
  }
  
  if(pthread_rwlock_unlock(&gem_lock) != 0) {
    fprintf(stderr, "Failed to unlock the gem_lock.\n");
    return;
  }
}

int configure_eustall() {
  int perf_fd;
  struct device_info *devinfo;
  
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
  
  printf("Device ID: 0x%X\n", devinfo->id);
  
  uint64_t properties[] = {
		PRELIM_DRM_I915_EU_STALL_PROP_BUF_SZ, p_size,
		PRELIM_DRM_I915_EU_STALL_PROP_SAMPLE_RATE, p_rate,
		PRELIM_DRM_I915_EU_STALL_PROP_POLL_PERIOD, p_poll_period,
		PRELIM_DRM_I915_EU_STALL_PROP_EVENT_REPORT_COUNT, p_event_count,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_CLASS, p_eng_class,
		PRELIM_DRM_I915_EU_STALL_PROP_ENGINE_INSTANCE, p_eng_inst,
  };
  
	struct drm_i915_perf_open_param param = {
		.flags = I915_PERF_FLAG_FD_CLOEXEC |
			 PRELIM_I915_PERF_FLAG_FD_EU_STALL |
			 I915_PERF_FLAG_DISABLED,
		.num_properties = sizeof(properties) / 16,
		.properties_ptr = (unsigned long long) properties,
	};

  /* Open the fd */
  perf_fd = ioctl_do(devinfo->fd, DRM_IOCTL_I915_PERF_OPEN, &param);
  if(perf_fd < 0) {
    fprintf(stderr, "Failed to open the perf file descriptor.\n");
    return -1;
  }
  
  /* Enable the fd */
  ioctl(perf_fd, I915_PERF_IOCTL_ENABLE, NULL, 0);
  
  /* Free up the device info */
  free_driver(devinfo);
  
  return perf_fd;
}
