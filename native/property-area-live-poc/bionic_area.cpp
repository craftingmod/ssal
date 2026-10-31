// Keep Android 16 r2 prop_area logic; intercept only its four file/mapping syscalls
// so the live report preserves the kernel syscall name and errno on failure.
#include <cerrno>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "async_safe/log.h"
#include "system_properties/prop_area.h"
#include "property_label.h"

extern "C" const char* ssal_current_context();

namespace {
const char* failure_operation = nullptr;
int failure_errno = 0;
bool fsetxattr_attempted = false;
bool fsetxattr_succeeded = false;
int fsetxattr_error = 0;
bool label_verified = false;

void record_failure(const char* operation, int error) {
  const int saved_errno = errno;
  if (failure_operation == nullptr) {
    failure_operation = operation;
    failure_errno = error;
  }
  fprintf(stderr,
          "stage=prop_area pid=%d tid=%ld requested_path=not_applicable dirfd=-1 "
          "flags=0 syscall=%s errno=%d selinux_context=%s\n",
          getpid(), syscall(SYS_gettid), operation, error, ssal_current_context());
  errno = saved_errno;
}

void record_open_failure(const char* path, int flags, mode_t mode, int error,
                         const char* purpose) {
  const int saved_errno = errno;
  if (failure_operation == nullptr) {
    failure_operation = "openat";
    failure_errno = error;
  }
  fprintf(stderr,
          "stage=prop_area pid=%d tid=%ld requested_path=%s dirfd=%d flags=0x%x mode=0%o "
          "syscall=openat errno=%d selinux_context=%s purpose=%s\n",
          getpid(), syscall(SYS_gettid), path, AT_FDCWD,
          static_cast<unsigned int>(flags), static_cast<unsigned int>(mode), error,
          ssal_current_context(), purpose);
  errno = saved_errno;
}

int ssal_open(const char* path, int flags, ...) {
  mode_t mode = 0;
  if ((flags & O_CREAT) != 0) {
    va_list args;
    va_start(args, flags);
    mode = static_cast<mode_t>(va_arg(args, int));
    va_end(args);
  }
  const long result = syscall(SYS_openat, AT_FDCWD, path, flags, mode);
  if (result < 0) {
    const char* purpose = (flags & O_CREAT) != 0 ? "map_prop_area_rw_create"
                                                : "map_prop_area_read";
    record_open_failure(path, flags, mode, errno, purpose);
  } else if ((flags & O_CREAT) != 0) {
    fprintf(stderr, "area_creation=PASS fd=%ld path=%s\n", result, path);
  }
  return static_cast<int>(result);
}

int ssal_fsetxattr(int fd, const char* name, const void* value, size_t size, int flags) {
  char label[256] = {};
  const ssize_t label_size = fgetxattr(fd, "security.selinux", label, sizeof(label) - 1);
  if (label_size < 0) {
    record_failure("fgetxattr", errno);
    return -1;
  }
  label[label_size] = '\0';
  fprintf(stderr, "area_initial_label=%s\n", label);
  if (!expected_property_label(label, static_cast<size_t>(label_size))) {
    errno = EACCES;
    record_failure("unexpected_created_file_label", errno);
    return -1;
  }
  fsetxattr_attempted = true;
  const long result = syscall(SYS_fsetxattr, fd, name, value, size, flags);
  if (result < 0) {
    fsetxattr_error = errno;
    record_failure("fsetxattr", errno);
  } else {
    fsetxattr_succeeded = true;
    const ssize_t size_after = fgetxattr(fd, "security.selinux", label, sizeof(label) - 1);
    if (size_after < 0) {
      record_failure("fgetxattr_after_relabel", errno);
      return -1;
    }
    if (!expected_property_label(label, static_cast<size_t>(size_after))) {
      errno = EACCES;
      record_failure("unexpected_relabelled_file_label", errno);
      return -1;
    }
    label_verified = true;
    fprintf(stderr, "area_label=PASS fsetxattr=PASS\n");
  }
  return static_cast<int>(result);
}

int ssal_ftruncate(int fd, off_t size) {
  if (!label_verified) {
    errno = EACCES;
    record_failure("label_verification", errno);
    return -1;
  }
  const long result = syscall(SYS_ftruncate, fd, size);
  if (result < 0) record_failure("ftruncate", errno);
  else fprintf(stderr, "ftruncate=PASS size=%lld\n", static_cast<long long>(size));
  return static_cast<int>(result);
}

void* ssal_mmap(void* address, size_t length, int protection, int flags, int fd, off_t offset) {
  const long result = syscall(SYS_mmap, address, length, protection, flags, fd, offset);
  if (result == -1) {
    record_failure("mmap", errno);
    return MAP_FAILED;
  }
  fprintf(stderr, "%s=PASS length=%zu\n",
          (protection & PROT_WRITE) != 0 ? "writer_mmap" : "reader_mmap", length);
  return reinterpret_cast<void*>(result);
}

int ssal_fstat(int fd, struct stat* info) {
  const int result = fstat(fd, info);
  if (result < 0) record_failure("fstat", errno);
  return result;
}
}  // namespace

extern "C" void ssal_bionic_reset_failure() {
  failure_operation = nullptr;
  failure_errno = 0;
  fsetxattr_attempted = false;
  fsetxattr_succeeded = false;
  fsetxattr_error = 0;
  label_verified = false;
}

extern "C" const char* ssal_bionic_failure_operation() { return failure_operation; }
extern "C" int ssal_bionic_failure_errno() { return failure_errno; }
extern "C" bool ssal_bionic_fsetxattr_attempted() { return fsetxattr_attempted; }
extern "C" bool ssal_bionic_fsetxattr_succeeded() { return fsetxattr_succeeded; }
extern "C" int ssal_bionic_fsetxattr_errno() { return fsetxattr_error; }

#define open ssal_open
#define fsetxattr ssal_fsetxattr
#define ftruncate ssal_ftruncate
#define mmap ssal_mmap
#define fstat ssal_fstat
#include "prop_area.cpp"
#undef fstat
#undef mmap
#undef ftruncate
#undef fsetxattr
#undef open
