#define wchar_t wchar_t_vulkan
#define intptr_t intptr_t_vulkan
#define uintptr_t uintptr_t_vulkan
#include <vulkan/vulkan_core.h>

/*****************************************************************************
  hacky declarations
*****************************************************************************/

struct anv_state {
        int64_t offset;
        uint32_t alloc_size;
        uint32_t idx;
        void *map;
};

struct vk_pipeline_robustness_state {
   VkPipelineRobustnessBufferBehaviorEXT storage_buffers;
   VkPipelineRobustnessBufferBehaviorEXT uniform_buffers;
   VkPipelineRobustnessBufferBehaviorEXT vertex_inputs;
   VkPipelineRobustnessImageBehaviorEXT images;
   char null_uniform_buffer_descriptor;
   char null_storage_buffer_descriptor;
};

struct anv_pipeline_stage {
   int stage;

   VkPipelineCreateFlags2KHR pipeline_flags;
   struct vk_pipeline_robustness_state rstate;

   const void *pipeline_pNext;
   const VkPipelineShaderStageCreateInfo *info;
};

/*****************************************************************************
  send_vulkan_ksp
  
  Sends a KSP back to userspace, along with a CPU stack.
*****************************************************************************/

#define MAX_VULKAN_OBJECT_NAMES 1024

void send_vulkan_ksp(void *ctx, __u64 addr, __u64 size) {
        struct uprobe_ksp_info *info;
        long err;
        
        info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
        if (!info) {
                ERR_PRINTK("send_vulkan_ksp failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return;
        }

        info->type = BPF_EVENT_TYPE_UPROBE_KSP;

        info->addr = addr;
        info->size = size;

        err = bpf_get_stack(ctx, &(info->ustack.addrs), sizeof(info->ustack.addrs), BPF_F_USER_STACK);
        if (err < 0) {
                WARN_PRINTK("send_vulkan_ksp failed to get a user stack: %ld", err);
        }

        info->pid   = bpf_get_current_pid_tgid() >> 32;
        info->tid   = bpf_get_current_pid_tgid();
        info->cpu   = bpf_get_smp_processor_id();
        info->time  = bpf_ktime_get_ns();
        bpf_get_current_comm(info->name, sizeof(info->name));

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
}

void send_vulkan_kernel_info(void *ctx, __u64 addr, char *name) {
        struct uprobe_kernel_info *info;
        long err;
        
        info = bpf_ringbuf_reserve(&rb, sizeof(*info), 0);
        if (!info) {
                ERR_PRINTK("send_vulkan_kernel_info failed to reserve in the ringbuffer.");
                err = bpf_ringbuf_query(&rb, BPF_RB_AVAIL_DATA);
                DEBUG_PRINTK("Unconsumed data: %lu", err);
                dropped_event = 1;
                return;
        }

        info->type = BPF_EVENT_TYPE_UPROBE_KERNEL_INFO;

        info->addr = addr;
        __builtin_memcpy(&(info->symbol), name, MAX_SYMBOL_SIZE);

        bpf_ringbuf_submit(info, BPF_RB_FORCE_WAKEUP);
}

/*****************************************************************************
  Shader Names
  
  Applications can call the Vulkan extension called "Debug Utilities," which
  allows you to attach a name (string) to objects - pipelines, pipeline caches,
  shader modules, etc.
  
  We can intercept these strings, filter out all but the ones associated with
  shader modules, and construct a map of VkShaderModule -> name.
*****************************************************************************/

char null_symbol[MAX_SYMBOL_SIZE];
char blorp_clear_str[MAX_SYMBOL_SIZE] = "blorp_clear";
char blorp_blit_str[MAX_SYMBOL_SIZE] = "blorp_blit";
char blorp_copy_str[MAX_SYMBOL_SIZE] = "blorp_copy";
   
struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, MAX_VULKAN_OBJECT_NAMES);
        __type(key, __u64);                                 /* The VkShaderModule */
        __type(value, char[MAX_SYMBOL_SIZE]); /* The name */
} object_names SEC(".maps");
   
SEC("uprobe//usr/lib/libvulkan_intel.so:vk_common_SetDebugUtilsObjectNameEXT")
int BPF_UPROBE(vk_common_SetDebugUtilsObjectNameEXT, void *this, VkDebugUtilsObjectNameInfoEXT *info_arg) {
        VkDebugUtilsObjectNameInfoEXT info = {};
        __u64 vk_shader_module;
        char (*shader_module_name)[MAX_SYMBOL_SIZE];
        long err;
        
        err = bpf_probe_read_user(&info, sizeof(info), info_arg);
        if (err) {
                WARN_PRINTK("vk_common_SetDebugUtilsObjectNameEXT failed to read the object name");
                return 0;
        }
        
        /* We only want shader modules */
        if (info.objectType != VK_OBJECT_TYPE_SHADER_MODULE) {
                return 0;
        }
        
        if (info.pObjectName) {
                vk_shader_module = info.objectHandle;
                
                bpf_map_update_elem(&object_names, &vk_shader_module, &null_symbol, 0);
                shader_module_name = bpf_map_lookup_elem(&object_names, &vk_shader_module);
                if (shader_module_name == NULL) return 0;
                bpf_probe_read_user_str(*shader_module_name, sizeof(*shader_module_name), info.pObjectName);
        }
        
        return 0;
}

/*****************************************************************************
  Shader GPU Addresses
  
  We can trace to get the GPU address that was assigned to each shader by
  seeing where it was allocated in the VM's pool of memory.
*****************************************************************************/

__u64 vulkan_canary_addr = UINT64_MAX;

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} wait_for_shader_bin_create SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u64);
} wait_for_add_executables SEC(".maps");

/* We'll see this in between the uprobe and uretprobe of anv_shader_bin_create */
SEC("uretprobe//usr/lib/libvulkan_intel.so:anv_state_pool_alloc")
int BPF_URETPROBE(anv_state_pool_alloc, __u64 ret) {
        __u32 zero = 0;
        bpf_map_update_elem(&wait_for_shader_bin_create, &zero, &ret, 0);
        DEBUG_PRINTK("anv_state_pool_alloc 0x%llx", ret);
        return 0;
}

/* We can now read the GPU address that was assigned to this shader module */
SEC("uretprobe//usr/lib/libvulkan_intel.so:anv_shader_bin_create")
int BPF_URETPROBE(anv_shader_bin_create, __u64 ret) {
        __u64 *lookup;
        __u32 zero = 0;
        __u64 addr, size;
        long err;
        struct anv_state *in_state;
        struct anv_state state = {};
        
        /* Look up the GPU address that anv_state_pool_alloc allocated */
        lookup = bpf_map_lookup_elem(&wait_for_shader_bin_create, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("anv_shader_bin_create, but no anv_state_pool_alloc");
                return 0;
        }
        in_state = (struct anv_state *)*lookup;
        if (!in_state) {
                WARN_PRINTK("anv_shader_bin_create got a NULL anv_state");
                return 0;
        }
        err = bpf_probe_read_user(&state, sizeof(state), in_state);
        if (err) {
                WARN_PRINTK("anv_shader_bin_create failed to read the anv_state");
                return 0;
        }
        addr = state.offset & 0xFFFFFFFFFFC0;
        size = state.alloc_size;
        DEBUG_PRINTK("anv_shader_bin_create: 0x%llx\n", addr);

        /* Make sure we don't reuse that address */
        bpf_map_delete_elem(&wait_for_shader_bin_create, &zero);
        
        /* Wait for anv_pipeline_add_executable to get the VkShaderModule,
           and thus, the name of this shader */
        bpf_map_update_elem(&wait_for_add_executables, &zero, &addr, 0);
        DEBUG_PRINTK("anv_shader_bin_create 0x%llx", addr);
        
        send_vulkan_ksp(ctx, addr, size);

        return 0;
}

/* We can trace this function to get the VkShaderModule that anv_shader_bin_create was just
   called for. */
SEC("uprobe//usr/lib/libvulkan_intel.so:anv_pipeline_add_executables")
int BPF_UPROBE(anv_pipeline_add_executables, void *pipeline_arg, struct anv_pipeline_stage *stage_arg) {
        struct anv_pipeline_stage stage = {};
        __u32 zero = 0;
        long err;
        __u64 shader_module, addr;
        void *lookup;
        char *name;
        VkPipelineShaderStageCreateInfo info;
        
        /* Get the VkShaderModule */
        err = bpf_probe_read_user(&stage, sizeof(stage), stage_arg);
        if (err) {
                WARN_PRINTK("anv_pipeline_add_executable failed to read the stage");
                return 0;
        }
        err = bpf_probe_read_user(&info, sizeof(info), stage.info);
        if (err) {
                WARN_PRINTK("anv_pipeline_add_executable failed to read the VkPipelineShaderStageCreateInfo");
                return 0;
        }
        shader_module = (__u64)info.module;
        
        /* Now lookup the GPU address that we got from the anv_shader_bin_create chain */
        lookup = bpf_map_lookup_elem(&wait_for_add_executables, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("anv_pipeline_add_executables, but no anv_shader_bin_create");
                return 0;
        }
        addr = (__u64)*((__u64 *)lookup);
        
        /* ensure that we don't reuse this address erroneously */
        bpf_map_update_elem(&wait_for_add_executables, &zero, &vulkan_canary_addr, 0);
        
        if (addr == vulkan_canary_addr) {
                WARN_PRINTK("anv_pipeline_add_executables without an anv_shader_bin_create");
                return 0;
        }
        
        /* Now lookup the shader name */
        lookup = bpf_map_lookup_elem(&object_names, &shader_module);
        if (lookup == NULL) {
                WARN_PRINTK("Didn't see an object name for VkShaderModule 0x%llx", shader_module);
                return 0;
        }
        name = lookup;
        
        send_vulkan_kernel_info(ctx, addr, name);
        
        return 0;
}

/*****************************************************************************
  Blorp Shaders
  
  These are built-in shaders in Mesa, so we hardcode their names. If any of them
  triggers after an anv_shader_bin_create, then we know that it was that kernel
  type, and we "consume" the value from anv_shader_bin_create.
*****************************************************************************/

/* If this retprobe triggers right after an anv_shader_bin_create,
   then the shader was the built-in "clear" kernel. In this case,
   anv_ */
SEC("uretprobe//usr/lib/libvulkan_intel.so:blorp_clear")
int BPF_URETPROBE(blorp_clear) {
        __u32 zero = 0;
        __u64 addr;
        void *lookup;
        char *name;
        
        /* Now lookup the GPU address that we got from the anv_shader_bin_create chain */
        lookup = bpf_map_lookup_elem(&wait_for_add_executables, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("anv_pipeline_add_executables, but no anv_shader_bin_create");
                return 0;
        }
        addr = (__u64)*((__u64 *)lookup);
        
        /* ensure that we don't reuse this address erroneously */
        bpf_map_update_elem(&wait_for_add_executables, &zero, &vulkan_canary_addr, 0);
        
        if (addr == vulkan_canary_addr) {
                WARN_PRINTK("anv_pipeline_add_executables without an anv_shader_bin_create");
                return 0;
        }
        
        name = (char *)&blorp_clear_str;
        
        send_vulkan_kernel_info(ctx, addr, name);
        
        return 0;
}

SEC("uretprobe//usr/lib/libvulkan_intel.so:blorp_blit")
int BPF_URETPROBE(blorp_blit) {
        __u32 zero = 0;
        __u64 addr;
        void *lookup;
        char *name;
        
        /* Now lookup the GPU address that we got from the anv_shader_bin_create chain */
        lookup = bpf_map_lookup_elem(&wait_for_add_executables, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("anv_pipeline_add_executables, but no anv_shader_bin_create");
                return 0;
        }
        addr = (__u64)*((__u64 *)lookup);
        
        /* ensure that we don't reuse this address erroneously */
        bpf_map_update_elem(&wait_for_add_executables, &zero, &vulkan_canary_addr, 0);
        
        if (addr == vulkan_canary_addr) {
                WARN_PRINTK("anv_pipeline_add_executables without an anv_shader_bin_create");
                return 0;
        }
        
        name = (char *)&blorp_blit_str;
        
        send_vulkan_kernel_info(ctx, addr, name);
        
        return 0;
}

SEC("uretprobe//usr/lib/libvulkan_intel.so:blorp_copy")
int BPF_URETPROBE(blorp_copy) {
        __u32 zero = 0;
        __u64 addr;
        void *lookup;
        char *name;
        
        /* Now lookup the GPU address that we got from the anv_shader_bin_create chain */
        lookup = bpf_map_lookup_elem(&wait_for_add_executables, &zero);
        if (lookup == NULL) {
                WARN_PRINTK("anv_pipeline_add_executables, but no anv_shader_bin_create");
                return 0;
        }
        addr = (__u64)*((__u64 *)lookup);
        
        /* ensure that we don't reuse this address erroneously */
        bpf_map_update_elem(&wait_for_add_executables, &zero, &vulkan_canary_addr, 0);
        
        if (addr == vulkan_canary_addr) {
                WARN_PRINTK("anv_pipeline_add_executables without an anv_shader_bin_create");
                return 0;
        }
        
        name = (char *)&blorp_copy_str;
        
        send_vulkan_kernel_info(ctx, addr, name);
        
        return 0;
}
