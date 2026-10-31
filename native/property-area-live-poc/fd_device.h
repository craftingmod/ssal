#pragma once

#include <sys/stat.h>
#include <sys/vfs.h>

inline bool is_procfs_fd(int fd) {
  struct statfs info {};
  return fstatfs(fd, &info) == 0 && info.f_type == 0x9fa0;
}

inline int fd_on_device(int fd, unsigned long long device) {
  struct stat info {};
  if (fstat(fd, &info) != 0) return -1;
  return static_cast<unsigned long long>(info.st_dev) == device ? 1 : 0;
}
