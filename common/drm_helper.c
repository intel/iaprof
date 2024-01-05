#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <inttypes.h>
#include <drm/i915_drm_prelim.h>

#include "drm_helper.h"

void ioctl_err(int err) {
  switch(err) {
    case EBADF:
      fprintf(stderr, "The file descriptor passed to ioctl was invalid.\n");
      break;
    case EINTR:
      fprintf(stderr, "The ioctl command was interrupted.\n");
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
    case ENXIO:
      fprintf(stderr, "The requested code is valid for the device, but the driver doesn't support it.\n");
      break;
    default:
      fprintf(stderr, "The ioctl error was unknown.\n");
      break;
  }
}

int ioctl_do(int fd, unsigned long request, void *arg)
{
  int ret;
  do {
    ret = ioctl(fd, request, arg);
  } while (ret == -1 && (errno == EINTR || errno == EAGAIN));
  return ret;
}


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
    if(ioctl_do(fd, DRM_IOCTL_VERSION, &version)){
      fprintf(stderr, "Failed to get the DRM version!\n");
      ioctl_err(errno);
      close(fd);
      fd = -1;
      continue;
    }
    
    /* If the driver name isn't "i915", go to the next one. */
    if(strcmp(version.name, "i915") != 0) {
      fprintf(stderr, "Found a driver called '%s', but it's not supported.\n", version.name);
      close(fd);
      fd = -1;
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

int open_sysfs_dir(int fd) {
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

bool read_fd_uint64(int fd, uint64_t *out_value) {
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

bool read_sysfs(int sysfs_dir_fd, const char *file_path, uint64_t *out_value) {
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

int get_drm_device_info(device_info *devinfo) {
  int sysfs_dir_fd, i;
  uint32_t devid = 0, ret;
  
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
  
  if(strcmp(devinfo->name, "i915") == 0) {
    struct drm_i915_getparam gp;
    memset(&gp, 0, sizeof(gp));
    gp.param = I915_PARAM_CHIPSET_ID;
    gp.value = (int *) &devid;
    ioctl(devinfo->fd, DRM_IOCTL_I915_GETPARAM, &gp, sizeof(gp));
    devinfo->id = devid;
  } else {
    fprintf(stderr, "The DRM driver '%s' is not supported. Aborting.\n", devinfo->name);
    return -1;
  }
  
  devinfo->graphics_ver = 0;
  devinfo->graphics_rel = 0;
  for(i = 0; i < num_pvc_ids; i++) {
    if(devinfo->id == pvc_ids[i]) {
      devinfo->graphics_ver = 12;
      devinfo->graphics_rel = 60;
    }
  }
  if(devinfo->graphics_ver == 0) {
    fprintf(stderr, "Only Ponte Vecchio is supported for now!\n");
    return -1;
  }
  
  return 0;
}

void free_driver(device_info *devinfo) {
  close(devinfo->fd);
  free(devinfo);
}
