#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/types.h>

#ifdef XE_DRIVER
#include <sys/capability.h>
#include <uapi/drm/xe_drm.h>
#else
#include <drm/i915_drm.h>
#include <drm/i915_drm_prelim.h>
#endif

#include "drm_helpers/drm_helpers.h"
#include "printers/debug/debug_printer.h"

void ioctl_err(int err)
{
        switch (err) {
        case EBADF:
                WARN("The file descriptor passed to ioctl was invalid.\n");
                break;
        case EINTR:
                WARN("The ioctl command was interrupted.\n");
                break;
        case EFAULT:
                WARN("The argp argument to ioctl is an invalid memory area.\n");
                break;
        case EINVAL:
                WARN("The request or argp argument to ioctl is not valid.\n");
                break;
        case ENOTTY:
                WARN("The file descriptor passed to ioctl was not the right type.\n");
                break;
        case ENXIO:
                WARN("The requested code is valid for the device, but the driver doesn't support it.\n");
                break;
        default:
                WARN("The ioctl error was unknown.\n");
                break;
        }
}

int ioctl_do(int fd, unsigned long request, void *arg)
{
        int ret;
        do {
                ret = ioctl(fd, request, arg);
        } while (ret == -1 && (errno == EINTR || errno == EAGAIN));
        return ret;
}

#define MAX_DRIVER_CHARS 16
int open_first_driver(device_info *devinfo)
{
        int i, fd;
        char filename[80], name[MAX_DRIVER_CHARS] = "";
        drm_version_t version;

        /* Loop until we successfully open a device */
        for (i = 0; i < 16; i++) {
                sprintf(filename, "%s%u", DRIVER_BASE, i);
                fd = open(filename, O_RDWR);
                if (fd == -1) {
                        WARN("Failed to open device: %s\n",
                                filename);
                        continue;
                }

                /* Read in the name/version of the device */
                memset(&version, 0, sizeof(version));
                memset(name, 0, MAX_DRIVER_CHARS);
                version.name_len = sizeof(name) - 1;
                version.name = name;
                if (ioctl_do(fd, DRM_IOCTL_VERSION, &version)) {
                        WARN("Failed to get the DRM version!\n");
                        ioctl_err(errno);
                        close(fd);
                        fd = -1;
                        continue;
                }

                /* If the driver name isn't "i915", go to the next one. */
                if ((strcmp(version.name, "i915") != 0) && (strcmp(version.name, "xe") != 0)) {
                        close(fd);
                        fd = -1;
                        continue;
                }

                /* Success */
                break;
        }

        /* We didn't find any devices */
        if (fd == -1) {
                WARN("Failed to find any devices.\n");
                return -1;
        }

        /* Copy the final values into the struct */
        strcpy(devinfo->name, version.name);
        devinfo->fd = fd;

        return 0;
}

int open_sysfs_dir(int fd)
{
        int ret_fd;
        struct stat st;
        char path[128];

        if (fstat(fd, &st) || !S_ISCHR(st.st_mode)) {
                return -1;
        }

        snprintf(path, sizeof(path), "/sys/dev/char/%d:%d", major(st.st_rdev),
                 minor(st.st_rdev));
        ret_fd = open(path, O_DIRECTORY);
        if (ret_fd < 0) {
                return ret_fd;
        }
        if (minor(st.st_rdev) >= 128) {
                /* We don't support renderD* file descriptors */
                return -1;
        }
        return ret_fd;
}

bool read_fd_uint64(int fd, uint64_t *out_value)
{
        char buf[32];
        int n;

        n = read(fd, buf, sizeof(buf) - 1);
        if (n < 0) {
                return false;
        }

        buf[n] = '\0';
        *out_value = strtoull(buf, 0, 0);

        return true;
}

bool read_sysfs(int sysfs_dir_fd, const char *file_path, uint64_t *out_value)
{
        bool res;
        int fd;

        fd = openat(sysfs_dir_fd, file_path, O_RDONLY);
        if (fd < 0) {
                return false;
        }

        res = read_fd_uint64(fd, out_value);
        close(fd);

        return res;
}

int get_drm_device_info(device_info *devinfo)
{
        int sysfs_dir_fd, i;

        sysfs_dir_fd = open_sysfs_dir(devinfo->fd);
        if (sysfs_dir_fd < 0) {
                WARN("Failed to open the sysfs dir.\n");
                return -1;
        }

#ifdef XE_DRIVER
        if (strcmp(devinfo->name, "xe") == 0) {
                struct drm_xe_device_query dq;
                struct drm_xe_query_config *qc;
                
                /* Get the size that we need to allocate */
                memset(&dq, 0, sizeof(dq));
                dq.query = DRM_XE_DEVICE_QUERY_CONFIG;
                if(ioctl_do(devinfo->fd, DRM_IOCTL_XE_DEVICE_QUERY, &dq)) {
                        WARN("Failed to get the size of the device config! Aborting.\n");
                        ioctl_err(errno);
                        return -1;
                }
                
                /* Fill in qc */
                qc = malloc(dq.size);
                dq.data = (uint64_t)qc;
                if(ioctl_do(devinfo->fd, DRM_IOCTL_XE_DEVICE_QUERY, &dq)) {
                        WARN("Failed to get the device config! Aborting.\n");
                        ioctl_err(errno);
                        return -1;
                }
                
                WARN("Device ID and revision: 0x%llx\n", qc->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID]);
                WARN("VA bits: 0x%llx\n", qc->info[DRM_XE_QUERY_CONFIG_VA_BITS]);
                
                devinfo->id = qc->info[DRM_XE_QUERY_CONFIG_REV_AND_DEVICE_ID] & 0xffff;
                devinfo->va_bits = qc->info[DRM_XE_QUERY_CONFIG_VA_BITS];
                free(qc);
#else
        uint32_t devid = 0;
        if (strcmp(devinfo->name, "i915") == 0) {
                struct drm_i915_getparam gp;
                memset(&gp, 0, sizeof(gp));
                gp.param = I915_PARAM_CHIPSET_ID;
                gp.value = (int *)&devid;
                ioctl(devinfo->fd, DRM_IOCTL_I915_GETPARAM, &gp, sizeof(gp));
                devinfo->id = devid;
#endif
        } else {
                WARN("The DRM driver '%s' is not supported. Aborting.\n", devinfo->name);
                return -1;
        }

        devinfo->graphics_ver = 0;
        devinfo->graphics_rel = 0;
        for (i = 0; i < num_pci_ids; i++) {
                if (devinfo->id == pci_ids[i]) {
                        devinfo->graphics_ver = 12;
                        devinfo->graphics_rel = 60;
                }
        }
        if (devinfo->graphics_ver == 0) {
                WARN("Your device (PCI ID 0x%x) isn't supported.\n", devinfo->id);
                return -1;
        }

        return 0;
}

void free_driver(device_info *devinfo)
{
        close(devinfo->fd);
#ifdef XE_DRIVER
        free(devinfo->gt_info);
#else
        free(devinfo->engine_info);
#endif
        free(devinfo);
}
