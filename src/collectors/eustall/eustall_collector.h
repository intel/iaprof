#pragma once

#include <inttypes.h>
#include <pthread.h>

#include "drm_helpers/drm_helpers.h"

#include "stores/buffer_profile.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"

#include "utils/array.h"

/******************************************************************************
* Defaults
******************************************************************************/

#define DEFAULT_SAMPLE_RATE 4 /* HW events per sample, max 7 in i915 */
/* XXX ^^^ increase i915 max as this is too low and generates excessive samples */
#define DEFAULT_DSS_BUF_SIZE (128 * 1024)
#define DEFAULT_USER_BUF_SIZE (64 * DEFAULT_DSS_BUF_SIZE)
#define DEFAULT_POLL_PERIOD_NS 1000000 /* userspace wakeup interval */
#define DEFAULT_EVENT_COUNT \
        1 /* aggregation: number of events to trigger poll read */

/******************************************************************************
* eustall_info
* *********
* Struct that stores information about the eustall "perf" buffer.
******************************************************************************/

extern pthread_cond_t eustall_deferred_attrib_cond;
extern pthread_mutex_t eustall_deferred_attrib_cond_mtx;
extern pthread_mutex_t eustall_waitlist_mtx;
extern array_t *eustall_waitlist;

struct eustall_info_t {
        int perf_fd;
        uint8_t perf_buf[DEFAULT_USER_BUF_SIZE];

        uint64_t matched, unmatched, guessed, deferred;
};
extern struct eustall_info_t eustall_info;

/******************************************************************************
* Status
* *********
* Return types for the eustall collector.
******************************************************************************/
enum eustall_status {
        EUSTALL_STATUS_OK,
        EUSTALL_STATUS_ERROR,
        EUSTALL_STATUS_NOTFOUND,
};

struct eustall_sample;
struct offset_profile;

int associate_sample(struct eustall_sample *sample, uint64_t file, uint32_t vm_id,
                     uint64_t gpu_addr, uint64_t offset,
                     uint16_t subslice, unsigned long long time);
int handle_eustall_samples(void *perf_buf, int len);
int init_eustall(device_info *devinfo);
void wakeup_eustall_deferred_attrib_thread();
void handle_deferred_eustalls();
void init_eustall_waitlist();

/***************************************
  * offset_profile
  ***************
  * This stores overall stall counts for a single buffer.
  ***************
  * Reason     Description
  ************************
  * Active     At least one instruction is dispatching into a pipeline.
  * Other      Other factors stalled the instruction's execution.
  * Control    The instruction was waiting for a Branch unit to become
  *            available.
  * Pipestall  The instruction won arbitration but could not be dispatched
  *            into a Floating-Point or Extended Math unit. This can occur
  *            due to a bank conflict with the General Register File (GRF).
  * Send       The instruction was waiting for a Send unit to become available.
  * Dist/Acc   The instruction was waiting for a Distance or Architecture
  *            Register File (ARF) dependency to resolve.
  * SBID       The instruction was waiting for a Software Scoreboard
  *            dependency to resolve.
  * Sync       The instruction was waiting for a thread synchronization
  *            dependency to resolve.
  * Inst Fetch The XVE (Xe Vector Engine) was waiting for an instruction to
  *            be returned from the instruction cache.
***************************************/

struct offset_profile {
        unsigned int active;
        unsigned int other;
        unsigned int control;
        unsigned int pipestall;
        unsigned int send;
        unsigned int dist_acc;
        unsigned int sbid;
        unsigned int sync;
        unsigned int inst_fetch;
};

/***************************************
  * eustall_sample
  ***************
  * This is the struct that we get from the kernel driver.
  * It's 101 bits.
  ***************
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
***************************************/
struct __attribute__((__packed__)) eustall_sample {
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

void handle_remaining_eustalls();
