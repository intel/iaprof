#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <string.h>

#include "iaprof.h"
#include "debug_i915_collector.h"

void init_debug_i915(int i915_fd, int pid)
{
        int debug_fd;
        int i;
        
        /* First, check if we've already initialized this PID. */
        for (i = 0; i < debug_i915_info.pid_index; i++) {
                if (debug_i915_info.pids[i] == pid) {
                        return;
                }
        }
        
        /* Open the fd to begin debugging this PID */
        struct prelim_drm_i915_debugger_open_param open = {};
        open.pid = pid;
        debug_fd = ioctl(i915_fd, PRELIM_DRM_IOCTL_I915_DEBUGGER_OPEN, &open);
        if (debug_fd < 0) {
                fprintf(stderr, "Failed to open the debug interface for PID %d.\n", pid);
                return;
        }
        
        debug_i915_info.pids[debug_i915_info.pid_index++] = pid;
        add_to_epoll_fd(debug_fd);
}

void handle_elf(unsigned char *data, uint64_t data_size)
{
        printf("Found an ELF!\n");
        
}

void handle_event_uuid(int debug_fd, struct prelim_drm_i915_debug_event *event)
{
        struct prelim_drm_i915_debug_event_uuid *uuid;
        struct prelim_drm_i915_debug_read_uuid read_uuid = {};
        char uuid_str[37];
        int retval, i;
        unsigned char *data;

        uuid = (struct prelim_drm_i915_debug_event_uuid *) event;

        /* Only look at UUIDs being created with a nonzero size */
        if (!(event->flags & PRELIM_DRM_I915_DEBUG_EVENT_CREATE)) {
                return;
        }
        if (!uuid->payload_size) {
                return;
        }
        
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
        data = (unsigned char *) read_uuid.payload_ptr;
        
        /* Check for the ELF magic bytes */
        if (*((uint32_t *) data) == 0x464c457f) {
                handle_elf(data, read_uuid.payload_size);
        }
}


int read_debug_i915_event(int fd)
{
        int retval, ack_retval;
        struct prelim_drm_i915_debug_event_ack ack_event = {};
        struct prelim_drm_i915_debug_event *event;
        
        event = (struct prelim_drm_i915_debug_event *) debug_i915_info.event_buff;
        
        memset(event, 0, sizeof(struct prelim_drm_i915_debug_event) + MAX_EVENT_SIZE);
        event->size = MAX_EVENT_SIZE;
        event->type = PRELIM_DRM_I915_DEBUG_EVENT_READ;
        event->flags = 0;

        retval = ioctl(fd, PRELIM_I915_DEBUG_IOCTL_READ_EVENT, event);

        if (retval != 0) {
                fprintf(stderr, "read_event failed with: %d\n", retval);
                return -1;
        } else if (event->flags & ~(PRELIM_DRM_I915_DEBUG_EVENT_CREATE |
                                    PRELIM_DRM_I915_DEBUG_EVENT_DESTROY |
                                    PRELIM_DRM_I915_DEBUG_EVENT_STATE_CHANGE |
                                    PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK)) {
                return -2;
        }

        /* ACK the event, otherwise the workload will stall. */
        if (event->flags & PRELIM_DRM_I915_DEBUG_EVENT_NEED_ACK) {
                ack_event.type = event->type;
                ack_event.seqno = event->seqno;
                ack_retval = ioctl(fd, PRELIM_I915_DEBUG_IOCTL_ACK_EVENT, &ack_event);
                if (ack_retval != 0) {
                        fprintf(stderr, "  Failed to ACK event!\n");
                        return -1;
                }
        }

        if (event->type == PRELIM_DRM_I915_DEBUG_EVENT_UUID) {
                handle_event_uuid(fd, event);
        }

        return 0;
}

void read_debug_i915_events(int fd)
{
        int result, max_loops;
        
        max_loops = 3;
        result = 0;
        do {
                result = read_debug_i915_event(fd);
                max_loops--;
        } while ((result == 0) && (max_loops != 0));
}

char *debug_i915_event_to_str(int debug_event)
{
        return debug_events[debug_event];
}
