#pragma once
#include "utils.h"

#define DRIVER_BASE "/dev/dri/card"

int open_first_driver()
{
  int i, fd;
  char filename[80], name[16] = "";
  drm_version_t version;

  /* Loop until we successfully open a device */
  for (i = 0; i < 16; i++) {
    sprintf(filename, "%s%u", DRIVER_BASE, i);
    fd = open(filename, O_RDWR);
    if (fd == -1) {
      fprintf(stderr, "Failed to open device: %s\n",
              filename);
      continue;
    }

    /* Read in the name/version of the device */
    memset(&version, 0, sizeof(version));
    version.name_len = sizeof(name) - 1;
    version.name = name;
    if (ioctl_do(fd, DRM_IOCTL_VERSION, &version)) {
      fprintf(stderr, "Failed to get the DRM version!\n");
      ioctl_err(errno);
      close(fd);
      fd = -1;
      continue;
    }


    /* If the driver name isn't "i915", go to the next one. */
    if (strcmp(version.name, "i915") != 0) {
      fprintf(stderr,
              "Found a driver called '%s', but it's not supported.\n",
              version.name);
      close(fd);
      fd = -1;
      continue;
    }

    /* Success */
    break;
  }

  /* We didn't find any devices */
  if (fd == -1) {
    fprintf(stderr, "Failed to find any devices.\n");
    return -1;
  }
        
  printf("Found device: %s\n", version.name);
  return fd;
}

/* Given a PRELIM_DRM_I915_DEBUG_EVENT_* macro, returns the string equivalent.
   Caller should free the string. */
static char *debug_events[] = {
  "PRELIM_DRM_I915_DEBUG_EVENT_NONE",
  "PRELIM_DRM_I915_DEBUG_EVENT_READ",
  "PRELIM_DRM_I915_DEBUG_EVENT_CLIENT",
  "PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT",
  "PRELIM_DRM_I915_DEBUG_EVENT_UUID",
  "PRELIM_DRM_I915_DEBUG_EVENT_VM",
  "PRELIM_DRM_I915_DEBUG_EVENT_VM_BIND",
  "PRELIM_DRM_I915_DEBUG_EVENT_CONTEXT_PARAM",
  "PRELIM_DRM_I915_DEBUG_EVENT_EU_ATTENTION",
  "PRELIM_DRM_I915_DEBUG_EVENT_ENGINES",
  "PRELIM_DRM_I915_DEBUG_EVENT_PAGE_FAULT",
};

char *i915_debug_event_to_str(int debug_event)
{
  return debug_events[debug_event];
}
