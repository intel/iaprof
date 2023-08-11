#include <drm/i915_drm_prelim.h>

#include "gpu_kernel_decoder.h"

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
  uint32_t addr;
  struct eustall_sample sample;
  
  for(i = 0; i < len; i += 64) {
    /*
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
    printf("=====\n");
    
    /* Print out the 64 bytes */
    for(n = 0; n < 64; ++n) {
      fprintf(stdout, "%02X%s", perf_buf[n + i],
          ( n + 1 ) % 16 == 0 ? "\n" : " " );
    }
    
    /* Interpret the 64-byte sample */
    memcpy(&sample, perf_buf + i, sizeof(struct eustall_sample));
    sample.ip &= 0x1fffffff;
    memcpy(&info, perf_buf + i + 48, sizeof(info));
    
    /* Print the fields that have values */
    printf("Size: %lu\n", sizeof(struct eustall_sample));
    printf("IP: 0x%08X\n", sample.ip);
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
  }
}
