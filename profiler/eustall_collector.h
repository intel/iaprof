#include <drm/i915_drm_prelim.h>

#include "gpu_kernel_decoder.h"
#include "gem_collector.h"

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

void handle_eustall_samples(uint8_t *perf_buf, int len) {
  struct prelim_drm_i915_stall_cntr_info info;
  int i, n;
  uint64_t addr, start, end;
  struct eustall_sample sample;
  GEM_ARR_TYPE *gem;
  
  for(i = 0; i < len; i += 64) {
    
    memcpy(&sample, perf_buf + i, sizeof(struct eustall_sample));
    memcpy(&info, perf_buf + i + 48, sizeof(info));
    
    addr = ((uint64_t) sample.ip) << 3;
    
    if(pthread_rwlock_rdlock(&gem_lock) != 0) {
      fprintf(stderr, "Failed to grab the gem_lock for reading.\n");
      return;
    }
    
    for(n = 0; n < gem_arr_used; n++) {
      gem = &gem_arr[n];
      start = gem->kinfo.data & 0xffffffff;
      end = start + gem->kinfo.data_sz;
      if((addr >= start) && (addr < end)) {
        gem->active += sample.active;
        gem->other += sample.other;
        gem->control += sample.control;
        gem->pipestall += sample.pipestall;
        gem->send += sample.send;
        gem->dist_acc += sample.dist_acc;
        gem->sbid += sample.sbid;
        gem->sync += sample.sync;
        gem->inst_fetch += sample.inst_fetch;
        break;
      }
    }
    
    if(pthread_rwlock_unlock(&gem_lock) != 0) {
      fprintf(stderr, "Failed to unlock the gem_lock.\n");
      return;
    }
    
#if 0
    printf("=====\n");
    /* Print the fields that have values */
    printf("Size: %lu\n", sizeof(struct eustall_sample));
    printf("IP: 0x%08x\n", sample.ip);
    printf("subslice: %" PRIu16 "\n", info.subslice);
    if(sample.active) printf("  active: %u\n", sample.active);
    if(sample.other) printf("  other: %u\n", sample.other);
    if(sample.control) printf("  control: %u\n", sample.control);
    if(sample.pipestall) printf("  pipestall: %u\n", sample.pipestall);
    if(sample.send) printf("  send: %u\n", sample.send);
    if(sample.dist_acc) printf("  dist_acc: %u\n", sample.dist_acc);
    if(sample.sbid) printf("  sbid: %u\n", sample.sbid);
    if(sample.sync) printf("  sync: %u\n", sample.sync);
    if(sample.inst_fetch) printf("  inst_fetch: %u\n", sample.inst_fetch);
    
    parse_origin(pid, (uint64_t) sample.ip);
    
    printf("=====\n");
#endif
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
