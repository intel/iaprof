/*
  i915 TEST
  =================
  
  This is a small test program to play around with the i915 performance counter interface.
*/

#include <unistd.h>
#include <poll.h>
#include <sys/wait.h>

#include "drm_helper.h"

int main() {
  device_info *devinfo;
  
  devinfo = open_first_driver();
  if(devinfo->fd == -1) {
    fprintf(stderr, "Failed to open any drivers. Aborting.\n");
    exit(1);
  }
  get_drm_device_id(devinfo);
  if(get_drm_device_info(devinfo) != 0) {
    fprintf(stderr, "Failed to get device info. Aborting.\n");
    exit(1);
  }
  
  free_driver(devinfo);
}
