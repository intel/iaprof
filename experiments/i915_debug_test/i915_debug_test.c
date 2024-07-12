#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <drm/i915_drm_prelim.h>

#include "utils.h"
#include "i915_utils.h"

static struct option long_options[] = {
  { "pid", required_argument, 0, 'p' }, { 0 }
};

#define MAX_EVENT_SIZE 4096

int poll_on_debug(int debug_fd)
{
  struct pollfd poll_fd = {
    .fd = debug_fd,
    .events = POLLIN,
    .revents = 0,
  };
  return poll(&poll_fd, 1, 1000);
}

void handle_event_uuid(int debug_fd, struct prelim_drm_i915_debug_event *event)
{
  struct prelim_drm_i915_debug_event_uuid *uuid;
  struct prelim_drm_i915_debug_read_uuid read_uuid = {};
  char uuid_str[37];
  int retval, i;
  unsigned char *data;
  
  uuid = (struct prelim_drm_i915_debug_event_uuid *) event;
  
  if (event->flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE) {
    if (uuid->payload_size) {
      read_uuid.client_handle = uuid->client_handle;
      read_uuid.handle = uuid->handle;
      read_uuid.payload_size = uuid->payload_size;
      read_uuid.payload_ptr = (uint64_t) malloc(uuid->payload_size);
      retval = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_READ_UUID, &read_uuid);
      
      if (retval != 0) {
        fprintf(stderr, "  Failed to read a UUID!\n");
        free((void *) read_uuid.payload_ptr);
        return;
      }
      
      memcpy(uuid_str, read_uuid.uuid, 37);
      printf("  Got UUID of size %llu: %s\n", read_uuid.payload_size, uuid_str);
      data = (unsigned char *) read_uuid.payload_ptr;
      for (i = 0; i < read_uuid.payload_size; i++) {
        if (i > 0) printf(":");
        printf("%02X", data[i]);
      }
      printf("\n");
      printf("%s\n", data);
    }
  }
}

int read_event(int debug_fd, struct prelim_drm_i915_debug_event *event)
{
  int retval, ack_retval;
  struct prelim_drm_i915_debug_event_ack ack_event = {};
  
  retval = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_READ_EVENT, event);
  
  if (retval != 0) {
    fprintf(stderr, "read_event failed with: %d\n", retval);
    return -1;
  } else if (event->flags & ~(PRELIM_DRM_I915_DEBUG_EVENT_CREATE |
                              PRELIM_DRM_I915_DEBUG_EVENT_DESTROY |
                              PRELIM_DRM_I915_DEBUG_EVENT_STATE_CHANGE |
                              PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK)) {
    return -2;
  }
  
  printf("Event: %s\n", i915_debug_event_to_str(event->type));
  
  /* Go ahead and ACK the event no matter what */
  if (event->flags & PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK) {
    printf("  ACKing event...\n");
    ack_event.type = event->type;
    ack_event.seqno = event->seqno;
    ack_retval = ioctl(debug_fd, PRELIM_I915_DEBUG_IOCTL_ACK_EVENT, &ack_event);
    if (ack_retval != 0) {
      fprintf(stderr, "  Failed to ACK event!\n");
      return -1;
    }
  }
  
  if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_UUID) {
    handle_event_uuid(debug_fd, event);
  }
  
  return 0;
}

int main(int argc, char **argv)
{
  int option_index, pid, fd, debug_fd,
      number_of_fds, max_loop_count, result;
  char c;
  struct prelim_drm_i915_debugger_open_param open = {};
  uint8_t event_buff[sizeof(struct prelim_drm_i915_debug_event) + MAX_EVENT_SIZE];
  struct prelim_drm_i915_debug_event *event;
  
  pid = 0;
  while (1) {
    option_index = 0;
    c = getopt_long(argc, argv, "p:", long_options, &option_index);
    if (c == -1) {
      break;
    }
    switch (c) {
    case 'p':
      pid = strtol(optarg, NULL, 10);
      break;
    }
  }
  
  if (pid == 0) {
    fprintf(stderr, "No PID specified!\n");
    return 1;
  }
  
  fd = open_first_driver();
  if (fd == -1) {
    fprintf(stderr, "Aborting!\n");
    return 1;
  }
  
  open.pid = pid;
  debug_fd = ioctl(fd, PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN, &open);
  if (debug_fd < 0) {
    fprintf(stderr, "Failed to open the debug interface for PID %d.\n", pid);
    return 1;
  }
  
  event = (struct prelim_drm_i915_debug_event *) event_buff;
  
  while (1) {
    
    /* Poll to see if there are any events */
    number_of_fds = poll_on_debug(debug_fd);
    if ((number_of_fds < 0) && (errno == EINVAL)) {
      fprintf(stderr, "Error polling!\n");
      break;
    } else if (number_of_fds <= 0) {
      continue;
    }
    
    /* Read the event(s) */
    result = 0;
    max_loop_count = 3;
    do {
      memset(event, 0, sizeof(struct prelim_drm_i915_debug_event));
      event->size = MAX_EVENT_SIZE;
      event->type = PRELIM_DRM_I915_DEBUG_EVENT_READ;
      event->flags = 0;
      
      result = read_event(debug_fd, event);
      max_loop_count--;
      
    } while ((result == 0) && (max_loop_count > 0));
  }
}
