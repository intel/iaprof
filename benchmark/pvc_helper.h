#include "i915_helper.h"

/* This file includes helpers that ONLY work on PVC--
   significant changes to offsets and alignments would be
   needed to get these to work on other GPU architectures. */
   
/* Surface */
#define SURFACE_2D  1
#define SURFACEFORMAT_R8_UNORM    0x140
#define GEN8_FLOATING_POINT_IEEE_754    0

/* Pipelines */
#define GFXPIPE(Pipeline,Opcode,Subopcode) ((3 << 29) |      \
            ((Pipeline) << 27) |  \
            ((Opcode) << 24) |  \
            ((Subopcode) << 16))
#define GEN7_PIPELINE_SELECT      GFXPIPE(1, 1, 4)
#define PIPELINE_SELECT_GPGPU      (2 << 0)
#define GEN9_PIPELINE_SELECTION_MASK    (3 << 8)
#define GEN8_3DSTATE_BINDING_TABLE_POOL_ALLOC  GFXPIPE(3, 1, 25)

/* GEN12 Pipelines */
#define GFXPIPE_G12(Pipeline,Opcode,Subopcode) ((3 << 29) |    \
            ((Pipeline) << 27) |  \
            ((Opcode) << 24) |  \
            ((Subopcode) << 18))
#define GEN12_STATE_COMPUTE_MODE      GFXPIPE(0, 1, 5)
#define GEN12_CFE_STATE        GFXPIPE_G12(2, 2, 0)
#define GEN12_COMPUTE_WALKER      GFXPIPE_G12(2, 2, 2)

/* Base address */
#define GEN8_STATE_BASE_ADDRESS      GFXPIPE(0, 1, 1)
#define BASE_ADDRESS_MODIFY      (1 << 0)

/* Interface descriptor */
#define BITRANGE(start, end) (end - start + 1)
struct pvc_interface_descriptor_data
{
  struct {
    uint32_t pad0: BITRANGE(0, 5);
    uint32_t kernel_start_pointer: BITRANGE(6, 31);
  } desc0;

  struct {
    uint32_t kernel_start_pointer_high: BITRANGE(0, 15);
    uint32_t pad0: BITRANGE(16, 31);
  } desc1;

  struct {
    uint32_t pad0: BITRANGE(0, 6);
    uint32_t software_exception_enable: BITRANGE(7, 7);
    uint32_t pad1: BITRANGE(8, 10);
    uint32_t maskstack_exception_enable: BITRANGE(11, 11);
    uint32_t pad2: BITRANGE(12, 12);
    uint32_t illegal_opcode_exception_enable: BITRANGE(13, 13);
    uint32_t pad3: BITRANGE(14, 15);
    uint32_t floating_point_mode: BITRANGE(16, 16);
    uint32_t pad4: BITRANGE(17, 17);
    uint32_t single_program_flow: BITRANGE(18, 18);
    uint32_t denorm_mode: BITRANGE(19, 19);
    uint32_t thread_preemption_disable: BITRANGE(20, 20);
    uint32_t pad5: BITRANGE(21, 31);
  } desc2;

  struct {
    uint32_t pad0: BITRANGE(0, 1);
    uint32_t sampler_count: BITRANGE(2, 4);
    uint32_t sampler_state_pointer: BITRANGE(5, 31);
  } desc3;

  struct {
    uint32_t binding_table_entry_count: BITRANGE(0, 4);
    uint32_t binding_table_pointer: BITRANGE(5, 20);
    uint32_t pad0: BITRANGE(21, 31);
  } desc4;
  
  struct {
    uint32_t num_threads_in_tg: BITRANGE(0, 9);
    uint32_t pad0: BITRANGE(10, 15);
    uint32_t shared_local_memory_size: BITRANGE(16, 20);
    uint32_t barrier_enable: BITRANGE(21, 21);
    uint32_t rounding_mode: BITRANGE(22, 23);
    uint32_t pad1: BITRANGE(24, 26);
    uint32_t thread_group_dispatch_size: BITRANGE(27, 27);
    uint32_t pad2: BITRANGE(28, 31);
  } desc5;

  struct {
    uint32_t pad0;
  } desc6;

  struct {
    uint32_t pad0;
  } desc7;
};


/* Surface state */
struct pvc_surface_state
{
	struct {
		uint32_t cube_pos_z: BITRANGE(0, 0);
		uint32_t cube_neg_z: BITRANGE(1, 1);
		uint32_t cube_pos_y: BITRANGE(2, 2);
		uint32_t cube_neg_y: BITRANGE(3, 3);
		uint32_t cube_pos_x: BITRANGE(4, 4);
		uint32_t cube_neg_x: BITRANGE(5, 5);
		uint32_t media_boundary_pixel_mode: BITRANGE(6, 7);
		uint32_t render_cache_read_write: BITRANGE(8, 8);
		uint32_t sampler_l2_bypass_disable: BITRANGE(9, 9);
		uint32_t vert_line_stride_ofs: BITRANGE(10, 10);
		uint32_t vert_line_stride: BITRANGE(11, 11);
		uint32_t tiled_mode: BITRANGE(12, 13);
		uint32_t horizontal_alignment: BITRANGE(14, 15);
		uint32_t vertical_alignment: BITRANGE(16, 17);
		uint32_t surface_format: BITRANGE(18, 26);     /**< BRW_SURFACEFORMAT_x */
		uint32_t astc_enable: BITRANGE(27, 27);
		uint32_t is_array: BITRANGE(28, 28);
		uint32_t surface_type: BITRANGE(29, 31);       /**< BRW_SURFACE_1D/2D/3D/CUBE */
	} ss0;

	struct {
		uint32_t qpitch: BITRANGE(0, 14);
		uint32_t sample_tap_discard_disable: BITRANGE(15, 15);
		uint32_t pad0: BITRANGE(16, 16);
		uint32_t double_fetch_disable: BITRANGE(17, 17);
		uint32_t corner_texel_mode: BITRANGE(18, 18);
		uint32_t base_mip_level: BITRANGE(19, 23);
		uint32_t memory_object_control: BITRANGE(24, 30);
		uint32_t unorm_path_in_color_pipe: BITRANGE(31, 31);
	} ss1;

	struct {
		uint32_t width: BITRANGE(0, 13);
		uint32_t pad0: BITRANGE(14, 15);
		uint32_t height: BITRANGE(16, 29);
		uint32_t pad1: BITRANGE(30, 30);
		uint32_t depth_stencil_resource: BITRANGE(31, 31);
	} ss2;

	struct {
		uint32_t pitch: BITRANGE(0, 17);
		uint32_t null_probing_enable: BITRANGE(18, 18);
		uint32_t standard_tiling_mode_ext: BITRANGE(19, 19);
		uint32_t pad0: BITRANGE(20, 20);
		uint32_t depth: BITRANGE(21, 31);
	} ss3;

	struct {
		uint32_t multisample_position_palette_index: BITRANGE(0, 2);
		uint32_t num_multisamples: BITRANGE(3, 5);
		uint32_t multisampled_surface_storage_format: BITRANGE(6, 6);
		uint32_t render_target_view_extent: BITRANGE(7, 17);
		uint32_t min_array_element: BITRANGE(18, 28);
		uint32_t rotation: BITRANGE(29, 30);
		uint32_t decompress_in_l3: BITRANGE(31, 31);
	} ss4;

	struct {
		uint32_t mip_count: BITRANGE(0, 3);
		uint32_t surface_min_lod: BITRANGE(4, 7);
		uint32_t mip_tail_start_lod: BITRANGE(8, 11);
		uint32_t yuv_bpt: BITRANGE(12, 13);
		uint32_t coherency_type: BITRANGE(14, 15);
		uint32_t l1_cache_control: BITRANGE(16, 17); /* since DG2, MBZ before */
		uint32_t tiled_resource_mode: BITRANGE(18, 19);
		uint32_t ewa_disable_for_cube: BITRANGE(20, 20);
		uint32_t y_offset: BITRANGE(21, 23);
		uint32_t pad1: BITRANGE(24, 24);
		uint32_t x_offset: BITRANGE(25, 31);
	} ss5;

	struct {
		uint32_t pad; /* Multisample Control Surface stuff */
	} ss6;

	struct {
		uint32_t resource_min_lod: BITRANGE(0, 11);
		uint32_t pad0: BITRANGE(12, 13);
		uint32_t disable_support_for_multigpu_atomics: BITRANGE(14, 14);
		uint32_t disable_support_for_multigpu_partwrite: BITRANGE(15, 15);
		uint32_t shader_channel_select_a: BITRANGE(16, 18);
		uint32_t shader_channel_select_b: BITRANGE(19, 21);
		uint32_t shader_channel_select_g: BITRANGE(22, 24);
		uint32_t shader_channel_select_r: BITRANGE(25, 27);
		uint32_t pad1: BITRANGE(28, 29);
		uint32_t memory_compression_enable: BITRANGE(30, 30);
		uint32_t memory_compression_mode: BITRANGE(31, 31);
	} ss7;

	struct {
		uint32_t base_addr_lo;
	} ss8;

	struct {
		uint32_t base_addr_hi;
	} ss9;

	struct {
		uint32_t pad0: BITRANGE(0, 11);
		uint32_t aux_base_addr_lo: BITRANGE(12, 31);
	} ss10;

	struct {
		uint32_t aux_base_addr_hi;
	} ss11;

	struct {
		uint32_t compression_format: BITRANGE(0, 4);
		uint32_t clear_address_lo: BITRANGE(5, 31);
	} ss12;

	struct {
		uint32_t clear_address_hi: BITRANGE(0, 15);
		uint32_t pad0: BITRANGE(16, 31);
	} ss13;

	struct {
		uint32_t reserved;
	} ss14;

	struct {
		uint32_t reserved;
	} ss15;
};

uint32_t pvc_fill_surface_state(struct batchbuffer *bb, struct buff *buf, uint32_t format, int is_dst) {
  struct pvc_surface_state *ss;
  uint32_t write_domain, read_domain, offset;
  uint64_t address;
  
  if(is_dst) {
    write_domain = read_domain = I915_GEM_DOMAIN_RENDER;
  } else {
    write_domain = 0;
    read_domain = I915_GEM_DOMAIN_RENDER;
  }
  
  i915_batchbuf_ptr_align(bb, 64);
  offset = i915_batchbuf_offset(bb);
  ss = i915_batchbuf_ptr(bb);
  i915_batchbuf_ptr_add(bb, 64);

  ss->ss0.surface_type = SURFACE_2D;
  ss->ss0.surface_format = format;
  ss->ss0.render_cache_read_write = 1;
  ss->ss0.vertical_alignment = 1; /* align 4 */
  ss->ss0.horizontal_alignment = 1; /* align 4 */

  /* TODO: Tiling is not supported. */

  address = i915_batchbuf_add_reloc(bb, bb->handle, buf->handle,
                                    read_domain, write_domain, 0,
                                    offset + 4 * 8, 0x0);

  ss->ss8.base_addr_lo = (uint32_t) address;
  ss->ss9.base_addr_hi = address >> 32;

  ss->ss2.height = i915_buff_height(buf) - 1;
  ss->ss2.width  = i915_buff_width(buf) - 1;
  ss->ss3.pitch  = buf->surface[0].stride - 1;

  ss->ss5.l1_cache_control = true;

  ss->ss7.shader_channel_select_r = 4;
  ss->ss7.shader_channel_select_g = 5;
  ss->ss7.shader_channel_select_b = 6;
  ss->ss7.shader_channel_select_a = 7;

  return offset;

}

uint32_t pvc_fill_binding_table(struct batchbuffer *bb, struct buff *buf) {
  uint32_t binding_table_offset;
  uint32_t *binding_table;
  
  i915_batchbuf_ptr_align(bb, 64);
  binding_table_offset = i915_batchbuf_offset(bb);
  binding_table = i915_batchbuf_ptr(bb);
  i915_batchbuf_ptr_add(bb, 64);
  
  binding_table[0] = pvc_fill_surface_state(bb, buf, SURFACEFORMAT_R8_UNORM, 1);
  return binding_table_offset;
}

uint32_t pvc_fill_kernel(struct batchbuffer *bb, const uint32_t kernel[][4], size_t size) {
  uint32_t *kernel_dst;
  uint32_t offset;

  i915_batchbuf_ptr_align(bb, 64);
  kernel_dst = i915_batchbuf_ptr(bb);
  offset = i915_batchbuf_offset(bb);

  memcpy(kernel_dst, kernel, size);

  i915_batchbuf_ptr_add(bb, size);

  return offset;
}

void pvc_fill_interface_descriptor(struct batchbuffer *bb,
                                       struct buff *dst,
                                       const uint32_t kernel[][4],
                                       size_t size,
                                       struct pvc_interface_descriptor_data *idd)
{
  uint32_t binding_table_offset, kernel_offset;

  binding_table_offset = pvc_fill_binding_table(bb, dst);
  kernel_offset = pvc_fill_kernel(bb, kernel, size);

  memset(idd, 0, sizeof(*idd));
  idd->desc0.kernel_start_pointer = (kernel_offset >> 6);

  idd->desc2.single_program_flow = 1;
  idd->desc2.floating_point_mode = GEN8_FLOATING_POINT_IEEE_754;

  idd->desc3.sampler_count = 0;      /* 0 samplers used */
  idd->desc3.sampler_state_pointer = 0;

  idd->desc4.binding_table_entry_count = 0;
  idd->desc4.binding_table_pointer = (binding_table_offset >> 5);

  idd->desc5.num_threads_in_tg = 1;
}

void pvc_emit_state_base_address(struct batchbuffer *bb) {
  uint32_t tmp;

  i915_batchbuf_out(bb, GEN8_STATE_BASE_ADDRESS | 0x14);            //dw0

  /* general */
  i915_batchbuf_out(bb, 0 | BASE_ADDRESS_MODIFY);                   //dw1-dw2
  i915_batchbuf_out(bb, 0);

  /* stateless data port */
  tmp = BASE_ADDRESS_MODIFY;
  i915_batchbuf_out(bb, 0 | tmp);              //dw3

  /* surface */
  i915_batchbuf_emit_reloc(bb, bb->handle, i915_batchbuf_offset(bb), bb->handle,
                           I915_GEM_DOMAIN_SAMPLER, //dw4-dw5
                           0, BASE_ADDRESS_MODIFY, 0x0);

  /* dynamic */
  i915_batchbuf_emit_reloc(bb, bb->handle, i915_batchbuf_offset(bb), bb->handle,
                           I915_GEM_DOMAIN_RENDER | I915_GEM_DOMAIN_INSTRUCTION, // dw6-dw7
                           0, BASE_ADDRESS_MODIFY, 0x0);

  /* indirect */
  i915_batchbuf_out(bb, 0);  //dw8-dw9
  i915_batchbuf_out(bb, 0);

  /* instruction */
  i915_batchbuf_emit_reloc(bb, bb->handle, i915_batchbuf_offset(bb), bb->handle,
                           I915_GEM_DOMAIN_INSTRUCTION,            //dw10-dw11
                           0, BASE_ADDRESS_MODIFY, 0x0);

  /* general state buffer size */
  i915_batchbuf_out(bb, 0xfffff000 | 1);                          //dw12
  /* dynamic state buffer size */
  i915_batchbuf_out(bb, 1 << 12 | 1);                             //dw13

  /* indirect object buffer size */
  i915_batchbuf_out(bb, 0xfffff000 | 1);

  /* intruction buffer size */
  i915_batchbuf_out(bb, 1 << 12 | 1);                             //dw15

  /* Bindless surface state base address */
  i915_batchbuf_out(bb, 0 | BASE_ADDRESS_MODIFY);                 //dw16
  i915_batchbuf_out(bb, 0);                                       //dw17
  i915_batchbuf_out(bb, 0xfffff000);                              //dw18

  /* Bindless sampler state base address */
  i915_batchbuf_out(bb, 0 | BASE_ADDRESS_MODIFY);                 //dw19
  i915_batchbuf_out(bb, 0);                                       //dw20
  i915_batchbuf_out(bb, 0);                                       //dw21
}

void pvc_emit_state_compute_mode(struct batchbuffer *bb) {
  uint32_t dword_length = 1;

  i915_batchbuf_out(bb, GEN12_STATE_COMPUTE_MODE | dword_length);
  i915_batchbuf_out(bb, 0);

  if (dword_length)
    i915_batchbuf_out(bb, 0);
}

void pvc_emit_state_binding_table_pool_alloc(struct batchbuffer *bb) {
  i915_batchbuf_out(bb, GEN8_3DSTATE_BINDING_TABLE_POOL_ALLOC | 2);
  i915_batchbuf_emit_reloc(bb, bb->handle, i915_batchbuf_offset(bb), bb->handle,
                           I915_GEM_DOMAIN_RENDER | I915_GEM_DOMAIN_INSTRUCTION,
                           0, 0, 0x0);
  i915_batchbuf_out(bb, 1 << 12);
}

void pvc_emit_cfe_state(struct batchbuffer *bb, uint32_t threads) {
  bool dfeud = 0;
  uint32_t max_threads;

  i915_batchbuf_out(bb, GEN12_CFE_STATE | (6 - 2));

  /* scratch buffer */
  i915_batchbuf_out(bb, 0);
#define CFE_CAN_DISABLE_FUSED_EU_DISPATCH(devid)  (IS_XEHPSDV(devid) || \
          IS_DG2(devid))


  i915_batchbuf_out(bb, 0);

#define _LEGACY_MODE (1 << 6)
  /* number of threads & urb entries */
  max_threads = threads > 64 ? threads : 64;
  i915_batchbuf_out(bb, (max_threads - 1) << 16 | (dfeud ? _LEGACY_MODE : 0));

  i915_batchbuf_out(bb, 0);
  i915_batchbuf_out(bb, 0);
}

void pvc_emit_compute_walk(struct batchbuffer *bb,
                           unsigned int x, unsigned int y,
                           unsigned int width, unsigned int height,
                           struct pvc_interface_descriptor_data *pidd,
                           uint8_t color) {
  uint32_t x_dim, y_dim, dword_length, mask;

  /*
   * Simply do SIMD16 based dispatch, so every thread uses
   * SIMD16 channels.
   *
   * Define our own thread group size, e.g 16x1 for every group, then
   * will have 1 thread each group in SIMD16 dispatch. So thread
   * width/height/depth are all 1.
   *
   * Then thread group X = width / 16 (aligned to 16)
   * thread group Y = height;
   */
  x_dim = (x + width + 15) / 16;
  y_dim = y + height;

  mask = (x + width) & 15;
  if (mask == 0)
    mask = (1 << 16) - 1;
  else
    mask = (1 << mask) - 1;

  dword_length = 0x26;
  i915_batchbuf_out(bb, GEN12_COMPUTE_WALKER | dword_length);  //dw0

  i915_batchbuf_out(bb, 0); /* debug object */    //dw1
  i915_batchbuf_out(bb, 0); /* indirect data length */  //dw2
  i915_batchbuf_out(bb, 0); /* indirect data offset */  //dw3

  /* SIMD size */
  /* SIMD16 | enable inline | Message SIMD16 */
  i915_batchbuf_out(bb, 1 << 30 | 1 << 25 | 1 << 17);    //dw4

  /* Execution mask */
  i915_batchbuf_out(bb, mask);        //dw5
  
  /* x/y/z max */
  i915_batchbuf_out(bb, (x_dim << 20) | (y_dim << 10) | 1);  //dw6

  /* x dim */
  i915_batchbuf_out(bb, x_dim);        //dw7

  /* y dim */
  i915_batchbuf_out(bb, y_dim);        //dw8

  /* z dim */
  i915_batchbuf_out(bb, 1);          //dw9

  /* group id x/y/z */
  i915_batchbuf_out(bb, x / 16);        //dw10
  i915_batchbuf_out(bb, y);          //dw11
  i915_batchbuf_out(bb, 0);          //dw12

  /* partition id / partition size */
  i915_batchbuf_out(bb, 0);          //dw13
  i915_batchbuf_out(bb, 0);          //dw14

  /* preempt x/y/z */
  i915_batchbuf_out(bb, 0);          //dw15
  i915_batchbuf_out(bb, 0);          //dw16
  i915_batchbuf_out(bb, 0);          //dw17

  i915_batchbuf_out(bb, 0);

  /* Interface descriptor data */
  for (int i = 0; i < 8; i++) {        //dw18-25 (XE2:dw19-26)
    i915_batchbuf_out(bb, ((uint32_t *) pidd)[i]);
  }

  /* Postsync data */
  i915_batchbuf_out(bb, 0);          //dw26
  i915_batchbuf_out(bb, 0);          //dw27
  i915_batchbuf_out(bb, 0);          //dw28
  i915_batchbuf_out(bb, 0);          //dw29
  i915_batchbuf_out(bb, 0);          //dw30

  /* Inline data */
  i915_batchbuf_out(bb, (uint32_t) color);      //dw31
  for (int i = 0; i < 7; i++) {              //dw32-38
    i915_batchbuf_out(bb, 0x0);
  }
}
