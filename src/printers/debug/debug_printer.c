#include "iaprof.h"

#include "printers/flamegraph/flamegraph_printer.h"

#include "collectors/bpf_i915/bpf_i915_collector.h"
#include "collectors/eustall/eustall_collector.h"

#include "gpu_parsers/shader_decoder.h"

#include "utils/utils.h"

void print_debug_kernel_profile(struct buffer_profile *gem)
{
        printf("kernel handle=%u gpu_addr=0x%llx size=%lu\n", gem->handle,
               gem->vm_bind_info.gpu_addr, gem->buff_sz);
/*         dump_buffer(gem->buff, gem->buff_sz, gem->handle); */
}

/* Prints all GPU kernels that we found */
void print_debug_profile()
{
        int i;
        struct buffer_profile *gem;
        
        /* Iterate over each buffer */
	for (i = 0; i < buffer_profile_used; i++) {
		gem = &buffer_profile_arr[i];

                /* Make sure the buffer is a GPU kernel, that we have a valid
                   PID, and that we have a copy of it */
		if (!gem->has_stalls)
			continue;
		if ((!gem->buff_sz) || (!gem->buff))
			continue;

                print_debug_kernel_profile(gem);
	}
        
}
