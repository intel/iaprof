/*
Copyright 2026 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "device_info.hpp"

#include <sys/sysmacros.h>

#define DRIVER_BASE      "/dev/dri/card"
#define MAX_DRIVER_CHARS (16)

#define for_each_gt(gts__, gt__)                      \
        /* Beginning condition */                     \
        for (int iter__ = 0; /* Finished condition */ \
             (iter__ < gts__->num_gt) &&              \
             (gt__ = &(gts__->gt_list[iter__]),       \
             1); /* Incrementing */                   \
             iter__ += 1)

static const u32 PCI_IDS[] = {
#if 0
        /* PVC */
        0x0b69,
        0x0bd0,
        0x0bd5,
        0x0bd6,
        0x0bd7,
        0x0bd8,
        0x0bd9,
        0x0bda,
        0x0bdb,
        0x0be0,
        0x0be1,
        0x0be5,
#endif

        /* LNL */
        0x6420,
        0x64a0,
        0x64b0,

        /* BMG */
        0xe20b
};
static constexpr int NUM_PCI_IDS = sizeof(PCI_IDS) / sizeof(u32);

static const u32 OA_REGISTERS[] = {
    /* PES0 (Performance Event Select) Registers,
        from 0x13000 to 0x130ff */
    0x13000, 0x00001801,
    0x13004, 0x00000000,
    0x13008, 0x00001802,
    0x1300c, 0x00000000,
    0x13010, 0x00000622,
    0x13014, 0x00000000,
    0x13018, 0x00000623,
    0x1301c, 0x00000000,
    0x13020, 0x00000605,
    0x13024, 0x00000000,
    0x13028, 0x0000060f,
    0x1302c, 0x00000000,
    0x13030, 0x00000603,
    0x13034, 0x00000000,
    0x13038, 0x00000601,
    0x1303c, 0x00000000,
    0x13040, 0x00000604,
    0x13044, 0x00000000,
    0x13048, 0x00000a0b,
    0x1304c, 0x00000000,
    0x13050, 0x00000a0a,
    0x13054, 0x00000000,
    0x13058, 0x00001804,
    0x1305c, 0x00000000,
    0x13060, 0x00001600,
    0x13064, 0x00000000,
    0x13068, 0x00000625,
    0x1306c, 0x00000000,
    0x13070, 0x00000626,
    0x13074, 0x00000000,
    0x130a8, 0x0000060b,
    0x130ac, 0x00000000,
    0x130b0, 0x00000600,
    0x130b4, 0x00000000,
    0x130b8, 0x00000606,
    0x130bc, 0x00000000,
    0x130c0, 0x00000614,
    0x130c4, 0x00000000,
    0x130c8, 0x00000624,
    0x130cc, 0x00000000,
    0x130d0, 0x00000a0e,
    0x130d4, 0x00000000,
    0x130d8, 0x00000a0d,
    0x130dc, 0x00000000,
    0x130e0, 0x00000a15,
    0x130e4, 0x00000000,
    0x130e8, 0x00000a16,
    0x130ec, 0x00000000,
    0x130f0, 0x00000a13,
    0x130f4, 0x00000000,
    0x130f8, 0x00000a14,
    0x130fc, 0x00000000,

    /* PES1 (Performance Event Select) Registers,
        from 0x13200 to 0x133ff */
    0x13300, 0x00005a00,
    0x13304, 0x00000000,
    0x13500, 0x00005a00,
    0x13504, 0x00000000,
    0x13700, 0x00005a00,
    0x13704, 0x00000000,
    0x13308, 0x00004405,
    0x1330c, 0x00000000,
    0x13508, 0x00004405,
    0x1350c, 0x00000000,
    0x13708, 0x00004405,
    0x1370c, 0x00000000,
    0x13310, 0x00006805,
    0x13314, 0x00000000,
    0x13510, 0x00006805,
    0x13514, 0x00000000,
    0x13710, 0x00006805,
    0x13714, 0x00000000,
    0x13318, 0x00006002,
    0x1331c, 0x00000000,

    /* PES2 (Performance Event Select) Registers,
        from 0x13400 to 0x135ff */
    0x13518, 0x00006002,
    0x1351c, 0x00000000,

    /* PES3 (Performance Event Select) Registers,
        from 0x13400 to 0x135ff */
    0x13718, 0x00006002,
    0x1371c, 0x00000000,
    0x13320, 0x00006012,
    0x13324, 0x00000000,
    0x13520, 0x00006012,
    0x13524, 0x00000000,
    0x13720, 0x00006012,
    0x13724, 0x00000000,
    0x13328, 0x00006011,
    0x1332c, 0x00000000,
    0x13528, 0x00006011,
    0x1352c, 0x00000000,
    0x13728, 0x00006011,
    0x1372c, 0x00000000,
    0x13330, 0x0000600f,
    0x13334, 0x00000000,
    0x13530, 0x0000600f,
    0x13534, 0x00000000,
    0x13730, 0x0000600f,
    0x13734, 0x00000000,
    0x13338, 0x00006010,
    0x1333c, 0x00000000,
    0x13538, 0x00006010,
    0x1353c, 0x00000000,
    0x13738, 0x00006010,
    0x1373c, 0x00000000,
    0x13340, 0x00006015,
    0x13344, 0x00000000,
    0x13540, 0x00006015,
    0x13544, 0x00000000,
    0x13740, 0x00006015,
    0x13744, 0x00000000,
    0x13348, 0x00004600,
    0x1334c, 0x00000000,
    0x13548, 0x00004600,
    0x1354c, 0x00000000,
    0x13748, 0x00004600,
    0x1374c, 0x00000000,
    0x13350, 0x00004601,
    0x13354, 0x00000000,
    0x13550, 0x00004601,
    0x13554, 0x00000000,
    0x13750, 0x00004601,
    0x13754, 0x00000000,
    0x13358, 0x00005e0a,
    0x1335c, 0x00000000,
    0x13558, 0x00005e0a,
    0x1355c, 0x00000000,
    0x13758, 0x00005e0a,
    0x1375c, 0x00000000,
    0x13360, 0x00005e0b,
    0x13364, 0x00000000,
    0x13560, 0x00005e0b,
    0x13564, 0x00000000,
    0x13760, 0x00005e0b,
    0x13764, 0x00000000,
    0x13368, 0x00005e00,
    0x1336c, 0x00000000,
    0x13568, 0x00005e00,
    0x1356c, 0x00000000,
    0x13768, 0x00005e00,
    0x1376c, 0x00000000,
    0x13370, 0x00005e01,
    0x13374, 0x00000000,
    0x13570, 0x00005e01,
    0x13574, 0x00000000,
    0x13378, 0x00005e04,
    0x1337c, 0x00000000,
    0x13578, 0x00005e04,
    0x1357c, 0x00000000,
    0x13778, 0x00005e04,
    0x1377c, 0x00000000,
    0x13380, 0x00005c00,
    0x13384, 0x00000000,
    0x13580, 0x00005c00,
    0x13584, 0x00000000,
    0x13780, 0x00005c00,
    0x13784, 0x00000000,
    0x13388, 0x00005009,
    0x1338c, 0x00000000,
    0x13588, 0x00005009,
    0x1358c, 0x00000000,
    0x13788, 0x00005009,
    0x1378c, 0x00000000,
    0x13390, 0x00005008,
    0x13394, 0x00000000,
    0x13590, 0x00005008,
    0x13594, 0x00000000,
    0x13790, 0x00005008,
    0x13794, 0x00000000,
    0x13398, 0x00005000,
    0x1339c, 0x00000000,
    0x13598, 0x00005000,
    0x1359c, 0x00000000,
    0x13798, 0x00005000,
    0x1379c, 0x00000000,
    0x133a0, 0x00005010,
    0x133a4, 0x00000000,
    0x135a0, 0x00005010,
    0x135a4, 0x00000000,
    0x137a0, 0x00005010,
    0x137a4, 0x00000000,
    0x133a8, 0x00005013,
    0x133ac, 0x00000000,
    0x135a8, 0x00005013,
    0x135ac, 0x00000000,
    0x137a8, 0x00005013,
    0x137ac, 0x00000000,
    0x133b0, 0x00005012,
    0x133b4, 0x00000000,
    0x135b0, 0x00005012,
    0x135b4, 0x00000000,
    0x137b0, 0x00005012,
    0x137b4, 0x00000000,
    0x133b8, 0x00006400,
    0x133bc, 0x00000000,
    0x135b8, 0x00006400,
    0x135bc, 0x00000000,
    0x137b8, 0x00006400,
    0x137bc, 0x00000000,
    0x133c0, 0x00006401,
    0x133c4, 0x00000000,
    0x135c0, 0x00006401,
    0x135c4, 0x00000000,
    0x137c0, 0x00006401,
    0x137c4, 0x00000000,
    0x133c8, 0x00006402,
    0x133cc, 0x00000000,
    0x135c8, 0x00006402,
    0x135cc, 0x00000000,
    0x137c8, 0x00006402,
    0x137cc, 0x00000000,
    0x133d0, 0x00006403,
    0x133d4, 0x00000000,
    0x135d0, 0x00006403,
    0x135d4, 0x00000000,
    0x137d0, 0x00006403,
    0x137d4, 0x00000000,
    0xe458,  0x00000000,
};

static constexpr int NUM_OA_REGISTERS = sizeof(OA_REGISTERS) / sizeof(u32);

static int ioctl_do(int fd, unsigned long request, void *arg) {
    int ret;

    do {
        ret = ioctl(fd, request, arg);
    } while (ret == -1 && (errno == EINTR || errno == EAGAIN));

    return ret;
}

static bool open_driver(Device_Info *device_info) {
    /* @TODO: Need to handle cases where we have multiple compatible devices on the system
       (ex. LNL integrated graphics and a BMG card). Probably want the user to be able to decide. */


    int           i;
    int           fd                     = -1;
    drm_version_t version                = {};
    char          name[MAX_DRIVER_CHARS] = "";

    /* Loop until we successfully open a device */
    for (i = 0; i < 16; i += 1) {
        std::string filename = std::format("{}{}", DRIVER_BASE, i);

        fd = open(filename.c_str(), O_RDWR);
        if (fd == -1) {
            WARN("Failed to open device: {}\n", filename);
            continue;
        }

        /* Read in the name/version of the device */
        memset(&version, 0, sizeof(version));
        memset(name, 0, MAX_DRIVER_CHARS);
        version.name_len = sizeof(name) - 1;
        version.name = name;

        if (ioctl_do(fd, DRM_IOCTL_VERSION, &version)) {
            WARN("Failed to get the DRM version! (errno = {})\n", errno);
            errno = 0;
            close(fd);
            fd = -1;
            continue;
        }

        if (strcmp(version.name, "xe") != 0) {
            close(fd);
            fd = -1;
            continue;
        }

        /* Success */
        INFO("Selected device: {}\n", filename);
        break;
    }

    /* We didn't find any devices */
    if (fd == -1) {
        WARN("Failed to find any devices.\n");
        return false;
    }

    /* Copy the final values into the struct */
    device_info->fd      = fd;
    device_info->cardnum = i;
    strcpy(device_info->name, version.name);

    return true;
}

static int open_sysfs_dir(int fd) {
    struct stat st;
    int         ret_fd;

    if (fstat(fd, &st) || !S_ISCHR(st.st_mode)) {
        return -1;
    }

    std::string path = std::format("/sys/dev/char/{}:{}", major(st.st_rdev), minor(st.st_rdev));

    ret_fd = open(path.c_str(), O_DIRECTORY);
    if (ret_fd < 0) {
        return ret_fd;
    }

    if (minor(st.st_rdev) >= 128) {
        /* We don't support renderD* file descriptors */
        close(ret_fd);
        return -1;
    }

    return ret_fd;
}

static bool query(Device_Info *device_info) {
    int sysfs_dir_fd = open_sysfs_dir(device_info->fd);
    if (sysfs_dir_fd < 0) {
        WARN("Failed to open the sysfs dir.\n");
        return -1;
    }

    /* Get the size that we need to allocate */
    struct drm_xe_device_query dq = {};
    dq.query = DRM_XE_DEVICE_QUERY_CONFIG;
    if(ioctl_do(device_info->fd, DRM_IOCTL_XE_DEVICE_QUERY, &dq)) {
        WARN("Failed to get the size of the device config! Aborting. (errno = {})\n", errno);
        return -1;
    }

    /* Fill in qc */
    struct drm_xe_query_config *qc = (struct drm_xe_query_config*)malloc(dq.size);
    dq.data = (uint64_t)qc;
    if(ioctl_do(device_info->fd, DRM_IOCTL_XE_DEVICE_QUERY, &dq)) {
        WARN("Failed to get the device config! Aborting. (errno = {})\n", errno);
        free(qc);
        return -1;
    }

    INFO("Device ID and revision: {:#x}\n", qc->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID]);

    device_info->id      = qc->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID] & 0xffff;
    device_info->va_bits = qc->info[DRM_XE_QUERY_CONFIG_VA_BITS];
    free(qc);

    device_info->graphics_ver = 0;
    device_info->graphics_rel = 0;
    for (int i = 0; i < NUM_PCI_IDS; i++) {
        if (device_info->id == PCI_IDS[i]) {
            device_info->graphics_ver = 12;
            device_info->graphics_rel = 60;
        }
    }
    if (device_info->graphics_ver == 0) {
        WARN("Your device (PCI ID {:#x}) isn't supported.\n", device_info->id);
        return -1;
    }

    close(sysfs_dir_fd);
    return true;
}

static void xe_add_prop(std::vector<struct drm_xe_ext_set_property> &props, u32 property, u64 value) {
    struct drm_xe_ext_set_property p = {};
    p.base.name = DRM_XE_EU_STALL_EXTENSION_SET_PROPERTY;
    p.property  = property;
    p.value     = value;
    props.push_back(p);
}

static void xe_link_props(std::vector<struct drm_xe_ext_set_property> &props) {
    for (size_t i = 0; i + 1 < props.size(); i++) {
        props[i].base.next_extension = (u64)&props[i + 1];
    }
    if (!props.empty()) {
        props.back().base.next_extension = 0;
    }
}

static struct drm_xe_query_gt_list *xe_query_gts(int fd) {
    struct drm_xe_device_query query = {};
    query.query = DRM_XE_DEVICE_QUERY_GT_LIST;

    if (ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)) {
        WARN("Failed to query GT list size. (errno = {})\n", errno);
        return nullptr;
    }

    auto *qg = (struct drm_xe_query_gt_list *)malloc(query.size);
    query.data = (u64)qg;

    if (ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)) {
        WARN("Failed to query GT list. (errno = {})\n", errno);
        free(qg);
        return nullptr;
    }

    return qg;
}

static struct drm_xe_query_eu_stall *xe_query_eu_stalls(int fd) {
    struct drm_xe_device_query query = {};
    query.query = DRM_XE_DEVICE_QUERY_EU_STALL;

    if (ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)) {
        WARN("Failed to query EU stall size. (errno = {})\n", errno);
        return nullptr;
    }

    auto *stall_info = (struct drm_xe_query_eu_stall *)malloc(query.size);
    query.data = (u64)stall_info;

    if (ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)) {
        WARN("Failed to query EU stall info. (errno = {})\n", errno);
        free(stall_info);
        return nullptr;
    }

    return stall_info;
}

int Device_Info::xe_eustall_fd() {
    int                           fd         = -1;
    struct drm_xe_query_gt_list  *qg         = nullptr;
    struct drm_xe_query_eu_stall *stall_info = nullptr;

    if ((qg = xe_query_gts(this->fd)) == nullptr) {
        WARN("Failed to get GT list.\n");
        goto out;
    }

    if ((stall_info = xe_query_eu_stalls(this->fd)) == nullptr) {
        WARN("Failed to get EU stall info.\n");
        goto out_free_qg;
    }

    this->record_size = stall_info->record_size;

    if (stall_info->num_sampling_rates == 0) {
        WARN("No sampling rates available!\n");
        goto out_free_stall;
    }

    {
        std::vector<struct drm_xe_ext_set_property> props;
        xe_add_prop(props, DRM_XE_EU_STALL_PROP_SAMPLE_RATE, stall_info->sampling_rates[stall_info->num_sampling_rates - 1]);
        xe_add_prop(props, DRM_XE_EU_STALL_PROP_WAIT_NUM_REPORTS, 1);

        bool found = false;
        struct drm_xe_gt *gt;
        for_each_gt(qg, gt) {
            if (gt->type == DRM_XE_QUERY_GT_TYPE_MAIN) {
                xe_add_prop(props, DRM_XE_EU_STALL_PROP_GT_ID, gt->gt_id);
                found = true;
            }
        }

        if (!found) {
            WARN("Failed to find any GTs of type DRM_XE_QUERY_GT_TYPE_MAIN!\n");
            goto out_free_stall;
        }

        xe_link_props(props);

        struct drm_xe_observation_param param = {
            .extensions       = 0,
            .observation_type = DRM_XE_OBSERVATION_TYPE_EU_STALL,
            .observation_op   = DRM_XE_OBSERVATION_OP_STREAM_OPEN,
            .param            = (u64)props.data(),
        };

        fd = ioctl_do(this->fd, DRM_IOCTL_XE_OBSERVATION, &param);
        if (fd < 0) {
            WARN("Failed to open the EU stall file descriptor. (errno = {})\n", errno);
            goto out_free_stall;
        }

        if (ioctl_do(fd, DRM_XE_OBSERVATION_IOCTL_ENABLE, NULL) < 0) {
            WARN("Failed to enable the EU stall file descriptor. (errno = {})\n", errno);
            fd = -1;
            goto out_free_stall;
        }
    }

out_free_stall:;
    free(stall_info);
out_free_qg:;
    free(qg);
out:;
    return fd;
}

static struct drm_xe_query_oa_units *xe_query_oa_units(int fd) {
    struct drm_xe_device_query query = {};
    query.query = DRM_XE_DEVICE_QUERY_OA_UNITS;

    if (ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)) {
        WARN("Failed to query OA units size. (errno = {})\n", errno);
        return nullptr;
    }

    auto *oa_units_info = (struct drm_xe_query_oa_units *)malloc(query.size);
    query.data = (u64)oa_units_info;

    if (ioctl_do(fd, DRM_IOCTL_XE_DEVICE_QUERY, &query)) {
        WARN("Failed to query OA units info. (errno = {})\n", errno);
        free(oa_units_info);
        return nullptr;
    }

    return oa_units_info;
}

static int xe_add_oa_config(Device_Info *device_info) {
    static const char *uuid = "0c47fabe-3bbf-4b82-9efb-ff7b30f73d90";

    std::string metric_path = std::format("/sys/class/drm/card{}/metrics/{}/id", device_info->cardnum, uuid);

    std::ifstream file(metric_path);
    if (file) {
        int config_id;
        file >> config_id;
        return config_id;
    }

    struct drm_xe_oa_config config = {};
    memcpy(&config.uuid, uuid, 36);
    config.regs_ptr = (u64)OA_REGISTERS;
    config.n_regs   = NUM_OA_REGISTERS / 2;

    struct drm_xe_observation_param param = {
        .extensions       = 0,
        .observation_type = DRM_XE_OBSERVATION_TYPE_OA,
        .observation_op   = DRM_XE_OBSERVATION_OP_ADD_CONFIG,
        .param            = (u64)&config,
    };

    int config_id = ioctl_do(device_info->fd, DRM_IOCTL_XE_OBSERVATION, &param);
    if (config_id < 0) {
        WARN("Failed to add the OA config! (errno = {})\n", errno);
        return -1;
    }

    return config_id;
}

static bool xe_get_oa_unit(int fd, struct drm_xe_oa_unit &unit) {
    auto *oa_units_info = xe_query_oa_units(fd);
    if (!oa_units_info) {
        WARN("Failed to get OA units info.\n");
        return false;
    }

    bool found = false;
    auto *poau = (u8 *)&oa_units_info->oa_units[0];
    for (u32 i = 0; i < oa_units_info->num_oa_units; i++) {
        auto *oau = (struct drm_xe_oa_unit *)poau;
        poau += sizeof(*oau) + oau->num_engines * sizeof(oau->eci[0]);

        if (oau->oa_unit_type == DRM_XE_OA_UNIT_TYPE_OAG) {
            memcpy(&unit, oau, sizeof(unit));
            found = true;
            break;
        }
    }

    free(oa_units_info);
    return found;
}

int Device_Info::xe_oa_fd() {
    struct drm_xe_oa_unit unit;
    if (!xe_get_oa_unit(this->fd, unit)) {
        WARN("Failed to get OA unit.\n");
        return -1;
    }

    this->oa_timestamp_freq = unit.oa_timestamp_freq;

    int config_id = xe_add_oa_config(this);
    if (config_id < 1) {
        WARN("Failed to add OA config.\n");
        return -1;
    }

    u64 period_exponent = (u64)std::log2(unit.oa_timestamp_freq) - 1;

    std::vector<drm_xe_ext_set_property> props;
    xe_add_prop(props, DRM_XE_OA_PROPERTY_OA_UNIT_ID,         unit.oa_unit_id);
    xe_add_prop(props, DRM_XE_OA_PROPERTY_SAMPLE_OA,          1);
    xe_add_prop(props, DRM_XE_OA_PROPERTY_OA_METRIC_SET,      config_id);
    xe_add_prop(props, DRM_XE_OA_PROPERTY_OA_FORMAT,          DRM_XE_OA_FMT_TYPE_PEC | (1 << 8) | (1 << 16) | (0 << 24));
    xe_add_prop(props, DRM_XE_OA_PROPERTY_OA_DISABLED,        1);
    xe_add_prop(props, DRM_XE_OA_PROPERTY_OA_PERIOD_EXPONENT, period_exponent);
    xe_link_props(props);

    struct drm_xe_observation_param param = {
        .extensions       = 0,
        .observation_type = DRM_XE_OBSERVATION_TYPE_OA,
        .observation_op   = DRM_XE_OBSERVATION_OP_STREAM_OPEN,
        .param            = (u64)props.data(),
    };

    int fd = ioctl_do(this->fd, DRM_IOCTL_XE_OBSERVATION, &param);
    if (fd < 0) {
        WARN("Failed to open the OA file descriptor. (errno = {})\n", errno);
        return -1;
    }

    struct drm_xe_oa_stream_info stream_info = {};
    if (ioctl_do(fd, DRM_XE_OBSERVATION_IOCTL_INFO, &stream_info) < 0) {
        WARN("Failed to get OA stream info. (errno = {})\n", errno);
    }
    this->oa_buf_size = stream_info.oa_buf_size;

    if (ioctl_do(fd, DRM_XE_OBSERVATION_IOCTL_ENABLE, NULL) < 0) {
        WARN("Failed to enable the OA file descriptor. (errno = {})\n", errno);
        close(fd);
        return -1;
    }

    return fd;
}

void Device_Info::init() {
    if (!open_driver(this)) {
        ERR("Failed to open any drivers.\n");
    }

    if (!query(this)) {
        ERR("Failed to get device info.\n");
    }

    this->eustall_fd = this->xe_eustall_fd();
    if (this->eustall_fd < 0) {
        ERR("Failed to get eustall fd.\n");
    }

    this->oa_fd = this->xe_oa_fd();
    if (this->oa_fd < 0) {
        ERR("Failed to get OA fd.\n");
    }
}

int Device_Info::get_eustall_fd() {
    return this->eustall_fd;
}

int Device_Info::get_oa_fd() {
    return this->oa_fd;
}

u64 Device_Info::canonicalize(u64 addr) {
    return (addr << (64 - this->va_bits)) >> (64 - this->va_bits);
}

u64 Device_Info::canonicalized_kernel_addr(u64 addr) {
    return this->canonicalize(addr) & (~0xff);
}

Device_Info::~Device_Info() {
    close(this->fd);
}
