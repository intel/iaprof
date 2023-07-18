#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <inttypes.h>
#include <xf86drm.h>
#include <libdrm/drm.h>
#include <i915_drm.h>

/*******************
*    DISCOVERY     *
*******************/

struct drm_i915_query {
	__u32 num_items;
	__u32 flags;
	__u64 items_ptr;
};

struct drm_i915_query_topology_info {
	__u16 flags;
	__u16 max_slices;
	__u16 max_subslices;
	__u16 max_eus_per_subslice;
	__u16 subslice_offset;
	__u16 subslice_stride;
	__u16 eu_offset;
	__u16 eu_stride;
	__u8 data[];
};

#define DRIVER_BASE "/dev/dri/card"

typedef struct device_info {
  char name[16];
  int fd;
  uint64_t min_freq, max_freq;
} device_info;

void ioctl_err(int err) {
  switch(err) {
    case EBADF:
      fprintf(stderr, "The file descriptor passed to ioctl was invalid.\n");
      break;
    case EFAULT:
      fprintf(stderr, "The argp argument to ioctl is an invalid memory area.\n");
      break;
    case EINVAL:
      fprintf(stderr, "The request or argp argument to ioctl is not valid.\n");
      break;
    case ENOTTY:
      fprintf(stderr, "The file descriptor passed to ioctl was not the right type.\n");
      break;
  }
}

/* Opens a file descriptor for the first Intel driver that we see on the system. */
device_info *open_first_driver() {
  int i, fd;
  char filename[80], name[16] = "";
  drm_version_t version;
  device_info *devinfo;
  
  /* Loop until we successfully open a device */
  for(i = 0; i < 16; i++) {
    sprintf(filename, "%s%u", DRIVER_BASE, i);
    fd = open(filename, O_RDWR);
    if(fd == -1) {
      fprintf(stderr, "Failed to open device: %s\n", filename);
      continue;
    }
    
    /* Read in the name/version of the device */
    memset(&version, 0, sizeof(version));
    version.name_len = sizeof(name) - 1;
    version.name = name;
    if(drmIoctl(fd, DRM_IOCTL_VERSION, &version)){
      fprintf(stderr, "Failed to get the DRM version!\n");
      ioctl_err(errno);
      close(fd);
      continue;
    }
    
    /* Success */
    break;
  }
  
  /* We didn't find any devices */
  if(fd == -1) {
    fprintf(stderr, "Failed to find any devices.\n");
    return NULL;
  }
  
  /* Print out the name/version of the device */
  printf("Found a driver called: %s\n", version.name);
  
  /* Copy the final values into the struct */
  devinfo = calloc(1, sizeof(device_info));
  strcpy(devinfo->name, version.name);
  devinfo->fd = fd;
  
  return devinfo;
}

static int open_sysfs_dir(int fd) {
  int ret_fd;
  struct stat st;
  char path[128];
  
  if(fstat(fd, &st) || !S_ISCHR(st.st_mode)) {
    return -1;
  }
  
  snprintf(path, sizeof(path), "/sys/dev/char/%d:%d", major(st.st_rdev), minor(st.st_rdev));
  ret_fd = open(path, O_DIRECTORY);
  if(ret_fd < 0) {
    return ret_fd;
  }
  if(minor(st.st_rdev) >= 128) {
    /* We don't support renderD* file descriptors */
    return -1;
  }
  return ret_fd;
}

static bool read_fd_uint64(int fd, uint64_t *out_value) {
  char buf[32];
  int n;
  
  n = read(fd, buf, sizeof(buf) - 1);
  if(n < 0) {
    return false;
  }
  
  buf[n] = '\0';
  *out_value = strtoull(buf, 0, 0);
  
  return true;
}

static bool read_sysfs(int sysfs_dir_fd, const char *file_path, uint64_t *out_value) {
  bool res;
  int fd;
  
  fd = openat(sysfs_dir_fd, file_path, O_RDONLY);
  if(fd < 0) {
    return false;
  }
  
  res = read_fd_uint64(fd, out_value);
  close(fd);
  
  return res;
}

static int get_drm_device_info(device_info *devinfo) {
  int sysfs_dir_fd;
  
  sysfs_dir_fd = open_sysfs_dir(devinfo->fd);
  if(sysfs_dir_fd < 0) {
    fprintf(stderr, "Failed to open the sysfs dir.\n");
    return -1;
  }
  
  if(!read_sysfs(sysfs_dir_fd, "gt_min_freq_mhz", &(devinfo->min_freq)) ||
     !read_sysfs(sysfs_dir_fd, "gt_max_freq_mhz", &(devinfo->max_freq))) {
    fprintf(stderr, "Failed to read the minimum and maximum frequencies. Aborting.\n");
    close(sysfs_dir_fd);
    return -1;
  }
  
  printf("Minimum frequency: %" PRIu64 "\n", devinfo->min_freq);
  printf("Maximum frequency: %" PRIu64 "\n", devinfo->max_freq);
  
  return 0;
}

static uint32_t get_drm_device_id(device_info *devinfo) {
  uint32_t devid = 0, ret;
  
  if(strcmp(devinfo->name, "i915") == 0) {
    struct drm_i915_getparam gp;
    memset(&gp, 0, sizeof(gp));
    gp.param = I915_PARAM_CHIPSET_ID;
    gp.value = &devid;
    ioctl(devinfo->fd, DRM_IOCTL_I915_GETPARAM, &gp, sizeof(gp));
#if 0
  } else if(strcmp(devinfo->name, "xe") == 0) {
    struct drm_xe_query_config *config;
    struct drm_xe_device_query query = {
      .extensions = 0,
      .query = DRM_XE_DEVICE_QUERY_CONFIG,
      .size = 0,
      .data = 0,
    };
    ret = drmIoctl(devinfo->fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
    if(ret != 0) {
      fprintf(stderr, "Failed to query the Xe device.\n");
      exit(1);
    }
    config = malloc(query.size);
    query.data = (uint64_t) config;
    ret = drmIoctl(devinfo->fd, DRM_IOCTL_XE_DEVICE_QUERY, &query);
    if(ret != 0) {
      fprintf(stderr, "Failed to query the Xe device.\n");
      exit(1);
    }
    devid = config->info[XE_QUERY_CONFIG_REV_AND_DEVICE_ID] & 0xffff;
  }
#endif
  } else {
    fprintf(stderr, "The DRM driver '%s' is not supported. Aborting.\n", devinfo->name);
    exit(1);
  }
  
  return devid;
}

void free_driver(device_info *devinfo) {
  close(devinfo->fd);
  free(devinfo);
}

/*******************
*   CONFIGURATION  *
*******************/



/*
void configure_eustall() {
  
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
		.properties_ptr = to_user_pointer(properties),
	};
}
*/
