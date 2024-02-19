#include "printer.h"

#include "bpf/gem_collector.h"
#include "bpf/gem_collector.skel.h"
#include "eustall_collector.h"
#include "stack_printer.h"

int print_header()
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "EVENT");
	printf(" %-*.*s", TIME_LEN, TIME_LEN, "TIMESTAMP");
	printf(" %-*.*s", CPU_LEN, CPU_LEN, "CPU");
	printf(" %-*.*s", PID_LEN, PID_LEN, "PID");
	printf(" %-*.*s", TID_LEN, TID_LEN, "TID");
	printf(" %s\n", "ARGS");

	return 0;
}

int print_mapping(struct mapping_info *info)
{
	char *stack_str = NULL;

	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "mmap");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);

	/* ARGS */
	printf(" file=0x%llx handle=%u cpu_addr=0x%llx size=%llu offset=%llu ",
	       info->file, info->handle, info->cpu_addr, info->size,
	       info->offset);
	store_stack(info->pid, info->stackid, &stack_str);
	printf("%s", stack_str);
	printf("\n");

	return 0;
}

int print_unmap(struct unmap_info *info)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "unmap");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);
	printf(" file=0x%llx handle=%u cpu_addr=0x%llx size=%llu\n", info->file,
	       info->handle, info->cpu_addr, info->size);

	return 0;
}

int print_userptr(struct userptr_info *info)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "userptr");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);
	printf(" file=0x%llx handle=%u cpu_addr=0x%llx size=%llu\n", info->file,
	       info->handle, info->cpu_addr, info->size);

	return 0;
}

int print_vm_bind(struct vm_bind_info *info)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "vm_bind");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);
	printf(" file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx size=%llu\n",
	       info->file, info->handle, info->vm_id, info->gpu_addr,
	       info->size);

	return 0;
}

int print_vm_unbind(struct vm_unbind_info *info)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "vm_unbind");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);
	printf(" file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx size=%llu\n",
	       info->file, info->handle, info->vm_id, info->gpu_addr,
	       info->size);

	return 0;
}

int print_batchbuffer(struct execbuf_start_info *einfo,
		      struct vm_bind_info *info)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "batchbuffer");
	printf(" %-*llu", TIME_LEN, einfo->time);
	printf(" %-*u", CPU_LEN, einfo->cpu);
	printf(" %-*u", PID_LEN, einfo->pid);
	printf(" %-*u", TID_LEN, einfo->tid);
	printf(" file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx size=%llu\n",
	       einfo->file, einfo->bb_handle, einfo->vm_id, einfo->bb_offset,
	       einfo->batch_len);

	return 0;
}

int print_execbuf_start(struct execbuf_start_info *info)
{
	char *stack_str = NULL;

	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "execbuf_start");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);
	printf(" bb_handle=%u bb_offset=0x%llx ", info->bb_handle,
	       info->bb_offset);
	printf("ctx_id=%u vm_id=%u buffer_count=%u batch_len=0x%llx ",
	       info->ctx_id, info->vm_id, info->buffer_count, info->batch_len);
	printf("batch_start_offset=0x%x batch_index=%u ",
	       info->batch_start_offset, info->batch_index);
	store_stack(info->pid, info->stackid, &stack_str);
	printf("%s", stack_str);
	printf("\n");

	return 0;
}

/* Prints buffers that an execbuffer referenced through its vm_id */
int print_execbuf_gem(struct execbuf_start_info *info,
		      struct vm_bind_info *vinfo)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "execbuf_gem");
	printf(" %-*llu", TIME_LEN, info->time);
	printf(" %-*u", CPU_LEN, info->cpu);
	printf(" %-*u", PID_LEN, info->pid);
	printf(" %-*u", TID_LEN, info->tid);
	printf(" ctx_id=%u vm_id=%u", info->ctx_id, info->vm_id);
	printf(" file=0x%llx handle=%u vm_id=%u gpu_addr=0x%llx size=%llu\n",
	       vinfo->file, vinfo->handle, vinfo->vm_id, vinfo->gpu_addr,
	       vinfo->size);

	return 0;
}

int print_execbuf_end(struct execbuf_end_info *einfo)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "execbuf_end");
	printf(" %-*llu", TIME_LEN, einfo->time);
	printf(" %-*u", CPU_LEN, einfo->cpu);
	printf(" %-*u", PID_LEN, einfo->pid);
	printf(" %-*u", TID_LEN, einfo->tid);
	printf(" N/A\n");

	return 0;
}

int print_total_eustall(uint64_t num, unsigned long long time)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "eustall");
	printf(" %-*llu", TIME_LEN, time);
	printf(" %-*u", CPU_LEN, 0);
	printf(" %-*u", PID_LEN, 0);
	printf(" %-*u", TID_LEN, 0);
	printf(" num=%" PRIu64 " \n", num);

	return 0;
}

int print_eustall_reason(struct eustall_sample *sample)
{
	if (sample->active) {
		printf("active=%u ", sample->active);
	}
	if (sample->other) {
		printf("other=%u ", sample->other);
	}
	if (sample->control) {
		printf("control=%u ", sample->control);
	}
	if (sample->pipestall) {
		printf("pipestall=%u ", sample->pipestall);
	}
	if (sample->send) {
		printf("send=%u ", sample->send);
	}
	if (sample->dist_acc) {
		printf("dist_acc=%u ", sample->dist_acc);
	}
	if (sample->sbid) {
		printf("sbid=%u ", sample->sbid);
	}
	if (sample->sync) {
		printf("sync=%u ", sample->sync);
	}
	if (sample->inst_fetch) {
		printf("inst_fetch=%u ", sample->inst_fetch);
	}

	return 0;
}

int print_eustall(struct eustall_sample *sample, uint64_t gpu_addr,
		  uint64_t offset, uint32_t handle, uint16_t subslice,
		  unsigned long long time)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "eustall");
	printf(" %-*llu", TIME_LEN, time);
	printf(" %-*u", CPU_LEN, 0);
	printf(" %-*u", PID_LEN, 0);
	printf(" %-*u", TID_LEN, 0);
	printf(" handle=%u gpu_addr=0x%lx offset=0x%lx subslice=%" PRIu16 " ",
	       handle, gpu_addr, offset, subslice);
	print_eustall_reason(sample);
	printf("\n");

	return 0;
}

int print_eustall_churn(struct eustall_sample *sample, uint64_t gpu_addr,
			uint64_t offset, uint16_t subslice,
			unsigned long long time)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_churn");
	printf(" %-*llu", TIME_LEN, time);
	printf(" %-*u", CPU_LEN, 0);
	printf(" %-*u", PID_LEN, 0);
	printf(" %-*u", TID_LEN, 0);
	printf(" gpu_addr=0x%lx offset=0x%lx subslice=%" PRIu16 " ", gpu_addr,
	       offset, subslice);
	print_eustall_reason(sample);
	printf("\n");

	return 0;
}

int print_eustall_drop(struct eustall_sample *sample, uint64_t gpu_addr,
		       uint16_t subslice, unsigned long long time)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_drop");
	printf(" %-*llu", TIME_LEN, time);
	printf(" %-*u", CPU_LEN, 0);
	printf(" %-*u", PID_LEN, 0);
	printf(" %-*u", TID_LEN, 0);
	printf(" gpu_addr=0x%lx subslice=%" PRIu16 " ", gpu_addr, subslice);
	print_eustall_reason(sample);
	printf("\n");

	return 0;
}

int print_eustall_multichurn(struct eustall_sample *sample, uint64_t gpu_addr,
			     uint16_t subslice, unsigned long long time)
{
	printf("%-*.*s", EVENT_LEN, EVENT_LEN, "eustall_multichurn");
	printf(" %-*llu", TIME_LEN, time);
	printf(" %-*u", CPU_LEN, 0);
	printf(" %-*u", PID_LEN, 0);
	printf(" %-*u", TID_LEN, 0);
	printf(" gpu_addr=0x%lx subslice=%" PRIu16 " ", gpu_addr, subslice);
	print_eustall_reason(sample);
	printf("\n");

	return 0;
}
