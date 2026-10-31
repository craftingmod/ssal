#include "fd_device.h"

#include <cassert>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

int main() {
  FILE* file = tmpfile();
  assert(file != nullptr);
  const int fd = fileno(file);
  struct stat info {};
  assert(fstat(fd, &info) == 0);
  const auto device = static_cast<unsigned long long>(info.st_dev);
  assert(fd_on_device(fd, device) == 1);
  assert(fd_on_device(fd, device + 1) == 0);
  assert(!is_procfs_fd(fd));
  int proc_fd = open("/proc/self/fd", O_RDONLY | O_DIRECTORY);
  assert(proc_fd >= 0 && is_procfs_fd(proc_fd));
  assert(close(proc_fd) == 0 && !is_procfs_fd(proc_fd));
  const int alias = dup(fd);
  assert(alias >= 0 && fd_on_device(alias, device) == 1);
  assert(close(alias) == 0 && fd_on_device(alias, device) == -1);
  assert(fclose(file) == 0);
}
