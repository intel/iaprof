#pragma once

#include <sys/ioctl.h>

void ioctl_err(int err)
{
  switch (err) {
  case EBADF:
          fprintf(stderr,
                  "The file descriptor passed to ioctl was invalid.\n");
          break;
  case EINTR:
          fprintf(stderr, "The ioctl command was interrupted.\n");
          break;
  case EFAULT:
          fprintf(stderr,
                  "The argp argument to ioctl is an invalid memory area.\n");
          break;
  case EINVAL:
          fprintf(stderr,
                  "The request or argp argument to ioctl is not valid.\n");
          break;
  case ENOTTY:
    fprintf(stderr,
            "The file descriptor passed to ioctl was not the right type.\n");
    break;
  case ENXIO:
    fprintf(stderr,
            "The requested code is valid for the device, but the driver doesn't support it.\n");
    break;
  default:
    fprintf(stderr, "The ioctl error was unknown.\n");
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
