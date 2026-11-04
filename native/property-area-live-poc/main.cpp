#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "system_properties/prop_area.h"
#include "property_label.h"

extern "C" void ssal_bionic_reset_failure();
extern "C" const char* ssal_bionic_failure_operation();
extern "C" int ssal_bionic_failure_errno();
extern "C" bool ssal_bionic_fsetxattr_attempted();
extern "C" bool ssal_bionic_fsetxattr_succeeded();
extern "C" int ssal_bionic_fsetxattr_errno();

namespace {
constexpr char kTarget[] = "u:r:ssal_guest_probe:s0";
constexpr char kPropertyDirContext[] = "u:object_r:ssal_guest_property_dir:s0";
constexpr char kPropertyDirectory[] = "/dev/__properties__";
constexpr char kAreaPath[] = "/dev/__properties__/ssal_guest_probe.area";
constexpr char kPropertyName[] = "ssal.guest.poc";
constexpr char kPropertyValue[] = "guest-area-ok";
constexpr unsigned long long kAreaSize = 128 * 1024;
constexpr long kTmpfsMagic = 0x01021994;
const char* current_context = nullptr;

struct Identity {
  char context[256] = {};
  unsigned long long executable_dev = 0;
  unsigned long long executable_ino = 0;
};

struct Evidence {
  const char* status = "failed";
  const char* operation = nullptr;
  const char* cleanup = "not_needed";
  int error = 0;
  char mount_namespace_before[128] = {};
  char mount_namespace_after[128] = {};
  char property_label[256] = {};
  unsigned long long host_dir_dev = 0;
  unsigned long long host_dir_ino = 0;
  unsigned long long area_dev = 0;
  unsigned long long area_ino = 0;
  unsigned long long area_size = 0;
  int host_mount_id = -1;
  int guest_mount_id = -1;
  int area_mount_id = -1;
  int fsetxattr_errno = 0;
  bool fsetxattr_attempted = false;
  bool fsetxattr_succeeded = false;
  bool writer_mapped = false;
  bool property_added = false;
  bool reader_mapped = false;
  bool property_found = false;
  bool readonly_value_match = false;
  bool host_area_separated = false;
  bool separate_mapping = false;
};

bool fail(Evidence* evidence, const char* operation, int error = 0);

struct AreaMappings {
  prop_area* writer = nullptr;
  prop_area* reader = nullptr;
  int area_fd = -1;

  ~AreaMappings() { close_all(); }

  void close_all() {
    if (reader != nullptr) prop_area::unmap_prop_area(&reader);
    if (writer != nullptr) prop_area::unmap_prop_area(&writer);
    if (area_fd >= 0) {
      close(area_fd);
      area_fd = -1;
    }
  }
};

void remember_failure(Evidence* evidence, const char* syscall_name, int error,
                      const char* operation = nullptr) {
  if (evidence->operation == nullptr) {
    evidence->operation = operation == nullptr ? syscall_name : operation;
    evidence->error = error;
  }
}

void syscall_failure(Evidence* evidence, const char* syscall_name, int error = errno,
                     const char* operation = nullptr) {
  fprintf(stderr, "syscall=%s errno=%d\n", syscall_name, error);
  remember_failure(evidence, syscall_name, error, operation);
}

void diagnostic_stat(const char* path, const char* stage) {
  struct stat info {};
  const int result = stat(path, &info);
  const int error = result == 0 ? 0 : errno;
  fprintf(stderr,
          "diagnostic=stat stage=%s pid=%d tid=%ld requested_path=%s dirfd=%d flags=0 "
          "syscall=stat errno=%d selinux_context=%s result=%s\n",
          stage, getpid(), syscall(SYS_gettid), path, AT_FDCWD, error,
          current_context == nullptr ? "unavailable" : current_context,
          result == 0 ? "ok" : "failed");
}

void diagnostic_readlink(const char* path, const char* stage) {
  char target[256];
  const ssize_t size = readlinkat(AT_FDCWD, path, target, sizeof(target) - 1);
  const int error = size < 0 ? errno : 0;
  if (size >= 0) target[size] = '\0';
  fprintf(stderr,
          "diagnostic=readlinkat stage=%s pid=%d tid=%ld requested_path=%s dirfd=%d "
          "flags=0 syscall=readlinkat errno=%d selinux_context=%s result=%s target=%s\n",
          stage, getpid(), syscall(SYS_gettid), path, AT_FDCWD, error,
          current_context == nullptr ? "unavailable" : current_context,
          size < 0 ? "failed" : "ok", size < 0 ? "" : target);
}

void diagnose_proc_identity_path() {
  const pid_t pid = getpid();
  const long tid = syscall(SYS_gettid);
  char task_attr[128];
  char process_attr[96];
  const char* paths[] = {"/proc", "/proc/thread-self", "/proc/thread-self/attr",
                         "/proc/thread-self/attr/current", "/proc/self/attr/current",
                         process_attr, task_attr};
  snprintf(task_attr, sizeof(task_attr), "/proc/%d/task/%ld/attr/current", pid, tid);
  snprintf(process_attr, sizeof(process_attr), "/proc/%d/attr/current", pid);
  diagnostic_readlink("/proc/thread-self", "current_identity");
  for (const char* path : paths) {
    diagnostic_stat(path, "current_identity");
  }
}

int openat_diagnostic(int dirfd, const char* path, int flags, mode_t mode,
                      const char* site, const char* purpose) {
  const long result = syscall(SYS_openat, dirfd, path, flags, mode);
  if (result < 0) {
    const int error = errno;
    fprintf(stderr,
            "stage=%s pid=%d tid=%ld requested_path=%s dirfd=%d flags=0x%x mode=0%o "
            "syscall=openat errno=%d selinux_context=%s purpose=%s\n",
            site, getpid(), syscall(SYS_gettid), path, dirfd,
            static_cast<unsigned int>(flags), static_cast<unsigned int>(mode), error,
            current_context == nullptr ? "unavailable" : current_context, purpose);
    if (strcmp(site, "current_identity") == 0 &&
        strcmp(path, "/proc/thread-self/attr/current") == 0) {
      diagnose_proc_identity_path();
    }
    errno = error;
  }
  return static_cast<int>(result);
}

void proc_path_failure(Evidence* evidence, const char* stage, const char* path,
                       const char* syscall_name, int error) {
  fprintf(stderr,
          "stage=%s pid=%d tid=%ld requested_path=%s dirfd=%d flags=0 "
          "syscall=%s errno=%d selinux_context=%s\n",
          stage, getpid(), syscall(SYS_gettid), path, AT_FDCWD, syscall_name, error,
          current_context == nullptr ? "unavailable" : current_context);
  remember_failure(evidence, syscall_name, error);
}

bool read_text(const char* path, char* output, size_t capacity, Evidence* evidence,
               const char* site, const char* purpose) {
  const int fd = openat_diagnostic(AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0, site, purpose);
  if (fd < 0) {
    remember_failure(evidence, "openat", errno);
    return false;
  }
  const ssize_t size = read(fd, output, capacity - 1);
  const int read_error = errno;
  close(fd);
  if (size < 0) {
    fprintf(stderr,
            "stage=%s pid=%d tid=%ld requested_path=%s dirfd=%d flags=0x%x "
            "syscall=read errno=%d selinux_context=%s purpose=%s\n",
            site, getpid(), syscall(SYS_gettid), path, AT_FDCWD,
            O_RDONLY | O_CLOEXEC, read_error,
            current_context == nullptr ? "unavailable" : current_context, purpose);
    remember_failure(evidence, "read", read_error);
    errno = read_error;
    return false;
  }
  output[size] = '\0';
  size_t length = static_cast<size_t>(size);
  while (length > 0 && (output[length - 1] == '\n' || output[length - 1] == '\0')) {
    output[--length] = '\0';
  }
  return true;
}

bool mount_namespace(char* output, size_t capacity, Evidence* evidence) {
  const ssize_t size = readlink("/proc/self/ns/mnt", output, capacity - 1);
  if (size < 0) {
    const int error = errno;
    proc_path_failure(evidence, "mount_namespace", "/proc/self/ns/mnt", "readlinkat", error);
    errno = error;
    return false;
  }
  output[size] = '\0';
  return true;
}

bool copy_environment(const char* name, char* output, size_t capacity, Evidence* evidence) {
  const char* value = getenv(name);
  if (value == nullptr || strlen(value) >= capacity) {
    return fail(evidence, "invalid_host_snapshot_environment");
  }
  memcpy(output, value, strlen(value) + 1);
  return true;
}

bool parse_environment_number(const char* name, unsigned long long* output,
                              Evidence* evidence) {
  const char* value = getenv(name);
  if (value == nullptr || *value == '\0') {
    return fail(evidence, "invalid_host_snapshot_environment");
  }
  char* end = nullptr;
  errno = 0;
  const unsigned long long parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0') {
    return fail(evidence, "invalid_host_snapshot_environment", errno);
  }
  *output = parsed;
  return true;
}

int mount_id_for_fd(int fd, Evidence* evidence) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
  char contents[4096];
  if (!read_text(path, contents, sizeof(contents), evidence, "mount_id_for_fd", "fdinfo")) {
    return -1;
  }
  const char* marker = strstr(contents, "mnt_id:");
  if (marker == nullptr) {
    if (evidence->operation == nullptr) evidence->operation = "fdinfo_mnt_id_parse";
    return -1;
  }
  return atoi(marker + strlen("mnt_id:"));
}

bool file_label(const char* path, char* output, size_t capacity, Evidence* evidence) {
  const ssize_t size = getxattr(path, "security.selinux", output, capacity - 1);
  if (size < 0) {
    syscall_failure(evidence, "getxattr");
    return false;
  }
  output[size] = '\0';
  return true;
}

bool current_identity(Identity* identity, Evidence* evidence) {
  if (!read_text("/proc/thread-self/attr/current", identity->context,
                 sizeof(identity->context), evidence, "current_identity", "selinux_context")) {
    return false;
  }
  current_context = identity->context;
  const int fd = openat_diagnostic(AT_FDCWD, "/proc/self/exe", O_PATH | O_CLOEXEC, 0,
                                   "current_identity", "executable_identity");
  if (fd < 0) {
    remember_failure(evidence, "openat", errno);
    return false;
  }
  struct stat executable {};
  if (fstat(fd, &executable) != 0) {
    syscall_failure(evidence, "fstat");
    close(fd);
    return false;
  }
  close(fd);
  identity->executable_dev = static_cast<unsigned long long>(executable.st_dev);
  identity->executable_ino = static_cast<unsigned long long>(executable.st_ino);
  return true;
}

struct ProcPathResult {
  const char* path;
  int open_errno = 0;
  int read_errno = -1;
  int close_errno = -1;
  bool open_succeeded = false;
  bool read_succeeded = false;
  bool close_attempted = false;
  char value[256] = {};
};

struct ProcComponentResult {
  const char* path;
  int stat_errno = 0;
  int readlink_errno = -1;
  unsigned int mode = 0;
  unsigned int uid = 0;
  unsigned int gid = 0;
  bool stat_succeeded = false;
  bool readlink_attempted = false;
  bool readlink_succeeded = false;
  char target[256] = {};
};

struct HostProcBoundary {
  unsigned int pid = 0;
  int root_open_errno = -1;
  int fd_dir_open_errno = -1;
  int fd_read_errno = -1;
  int signal_zero_errno = -1;
  bool root_opened = false;
  bool fd_dir_opened = false;
  bool fd_read_succeeded = false;
  bool signal_zero_allowed = false;
};

struct GuestRuntimeBoundary {
  unsigned long long guest_data_dev = 0;
  unsigned long long guest_data_ino = 0;
  unsigned long long guest_binder_rdev = 0;
  unsigned long long host_binder_rdev = 0;
  int guest_data_errno = 0;
  int guest_binder_errno = 0;
  int property_area_errno = 0;
  int property_socket_errno = 0;
  bool guest_data_matches_profile = false;
  bool guest_data_differs_host = false;
  bool guest_data_write_read_unlink = false;
  bool guest_binder_private = false;
  bool guest_binder_opened = false;
  bool guest_property_area_differs_host = false;
  bool guest_property_socket_absent = false;
};

void json_string(const char* value) {
  putchar('"');
  for (const unsigned char* cursor = reinterpret_cast<const unsigned char*>(value);
       *cursor != '\0'; ++cursor) {
    switch (*cursor) {
      case '"':
        fputs("\\\"", stdout);
        break;
      case '\\':
        fputs("\\\\", stdout);
        break;
      case '\n':
        fputs("\\n", stdout);
        break;
      case '\r':
        fputs("\\r", stdout);
        break;
      case '\t':
        fputs("\\t", stdout);
        break;
      default:
        if (*cursor < 0x20) {
          printf("\\u%04x", *cursor);
        } else {
          putchar(*cursor);
        }
    }
  }
  putchar('"');
}

void probe_proc_path(ProcPathResult* result) {
  constexpr int kFlags = O_RDONLY | O_CLOEXEC;
  const long fd = syscall(SYS_openat, AT_FDCWD, result->path, kFlags, 0);
  if (fd < 0) {
    result->open_errno = errno;
    return;
  }
  result->open_succeeded = true;

  const ssize_t size = syscall(SYS_read, static_cast<int>(fd), result->value,
                               sizeof(result->value) - 1);
  if (size < 0) {
    result->read_errno = errno;
  } else {
    result->read_succeeded = true;
    result->read_errno = 0;
    result->value[size] = '\0';
    size_t length = static_cast<size_t>(size);
    while (length > 0 && (result->value[length - 1] == '\n' ||
                          result->value[length - 1] == '\r' ||
                          result->value[length - 1] == '\0')) {
      result->value[--length] = '\0';
    }
  }

  result->close_attempted = true;
  if (syscall(SYS_close, static_cast<int>(fd)) != 0) {
    result->close_errno = errno;
  } else {
    result->close_errno = 0;
  }
}

void probe_proc_component(ProcComponentResult* result, bool is_symlink) {
  struct stat info {};
  if (syscall(SYS_newfstatat, AT_FDCWD, result->path, &info, 0) != 0) {
    result->stat_errno = errno;
  } else {
    result->stat_succeeded = true;
    result->stat_errno = 0;
    result->mode = static_cast<unsigned int>(info.st_mode);
    result->uid = static_cast<unsigned int>(info.st_uid);
    result->gid = static_cast<unsigned int>(info.st_gid);
  }
  if (!is_symlink) return;
  result->readlink_attempted = true;
  const ssize_t size = syscall(SYS_readlinkat, AT_FDCWD, result->path,
                               result->target, sizeof(result->target) - 1);
  if (size < 0) {
    result->readlink_errno = errno;
  } else {
    result->readlink_succeeded = true;
    result->readlink_errno = 0;
    result->target[size] = '\0';
  }
}

bool probe_host_proc_boundaries(HostProcBoundary* results, size_t capacity,
                                size_t* result_count) {
  // O_PATH and getdents inspect procfs reachability without opening Host FD targets.
  const char* cursor = getenv("SSAL_HOST_CORE_PIDS");
  if (cursor == nullptr || *cursor == '\0') return false;
  *result_count = 0;
  while (*cursor != '\0') {
    if (*result_count == capacity) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long parsed = strtoul(cursor, &end, 10);
    if (errno != 0 || end == cursor || parsed == 0 || parsed > 0x7fffffffUL ||
        (*end != '\0' && *end != ',')) {
      return false;
    }
    HostProcBoundary& result = results[(*result_count)++];
    result.pid = static_cast<unsigned int>(parsed);

    char path[64];
    snprintf(path, sizeof(path), "/proc/%u/root", result.pid);
    const long root_fd = syscall(SYS_openat, AT_FDCWD, path, O_PATH | O_CLOEXEC, 0);
    if (root_fd < 0) {
      result.root_open_errno = errno;
    } else {
      result.root_opened = true;
      result.root_open_errno = 0;
      (void)syscall(SYS_close, static_cast<int>(root_fd));
    }

    snprintf(path, sizeof(path), "/proc/%u/fd", result.pid);
    const long fd_dir = syscall(SYS_openat, AT_FDCWD, path,
                                O_RDONLY | O_DIRECTORY | O_CLOEXEC, 0);
    if (fd_dir < 0) {
      result.fd_dir_open_errno = errno;
    } else {
      result.fd_dir_opened = true;
      result.fd_dir_open_errno = 0;
      char entries[4096];
      const long read_result = syscall(SYS_getdents64, static_cast<int>(fd_dir),
                                       entries, sizeof(entries));
      if (read_result < 0) {
        result.fd_read_errno = errno;
      } else {
        result.fd_read_succeeded = true;
        result.fd_read_errno = 0;
      }
      (void)syscall(SYS_close, static_cast<int>(fd_dir));
    }

    const long signal_check = syscall(SYS_kill, result.pid, 0);
    result.signal_zero_errno = signal_check < 0 ? errno : 0;
    result.signal_zero_allowed = signal_check == 0;
    if (*end == ',') {
      cursor = end + 1;
      if (*cursor == '\0') return false;
    } else {
      cursor = end;
    }
  }
  return *result_count != 0;
}

bool env_number(const char* name, unsigned long long* output) {
  const char* value = getenv(name);
  if (value == nullptr || *value == '\0') return false;
  char* end = nullptr;
  errno = 0;
  const unsigned long long parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0') return false;
  *output = parsed;
  return true;
}

GuestRuntimeBoundary probe_guest_runtime_boundaries() {
  GuestRuntimeBoundary result;
  unsigned long long expected_data_dev = 0, expected_data_ino = 0;
  unsigned long long host_data_dev = 0, host_data_ino = 0;
  const bool expected_data = env_number("SSAL_GUEST_DATA_DEV", &expected_data_dev) &&
                             env_number("SSAL_GUEST_DATA_INO", &expected_data_ino);
  const bool host_data = env_number("SSAL_HOST_DATA_DEV", &host_data_dev) &&
                         env_number("SSAL_HOST_DATA_INO", &host_data_ino);
  struct stat data {};
  if (expected_data && host_data && stat("/data", &data) == 0) {
    result.guest_data_dev = static_cast<unsigned long long>(data.st_dev);
    result.guest_data_ino = static_cast<unsigned long long>(data.st_ino);
    result.guest_data_matches_profile = result.guest_data_dev == expected_data_dev &&
                                        result.guest_data_ino == expected_data_ino;
    result.guest_data_differs_host = result.guest_data_dev != host_data_dev ||
                                     result.guest_data_ino != host_data_ino;
  } else {
    result.guest_data_errno = errno == 0 ? EINVAL : errno;
  }

  char marker[128];
  snprintf(marker, sizeof(marker), "/data/local/tmp/.ssal-phase5a-child-%d", getpid());
  const int marker_fd = open(marker, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
  if (marker_fd < 0) {
    result.guest_data_errno = errno;
  } else {
    constexpr char value[] = "guest-data-ok";
    char readback[sizeof(value)] = {};
    const bool wrote = write(marker_fd, value, sizeof(value) - 1) ==
                           static_cast<ssize_t>(sizeof(value) - 1) &&
                       fsync(marker_fd) == 0 && lseek(marker_fd, 0, SEEK_SET) == 0;
    const bool read_ok = wrote && read(marker_fd, readback, sizeof(value) - 1) ==
                                      static_cast<ssize_t>(sizeof(value) - 1) &&
                         memcmp(readback, value, sizeof(value) - 1) == 0;
    const int saved_errno = errno;
    close(marker_fd);
    const bool removed = unlink(marker) == 0;
    result.guest_data_write_read_unlink = read_ok && removed;
    if (!result.guest_data_write_read_unlink) {
      result.guest_data_errno = saved_errno == 0 ? EIO : saved_errno;
    }
  }

  if (!env_number("SSAL_HOST_BINDER_RDEV", &result.host_binder_rdev)) {
    result.guest_binder_errno = EINVAL;
  } else {
    struct stat binder {};
    if (stat("/dev/binder", &binder) != 0) {
      result.guest_binder_errno = errno;
    } else if (!S_ISCHR(binder.st_mode)) {
      result.guest_binder_errno = ENODEV;
    } else {
      result.guest_binder_rdev = static_cast<unsigned long long>(binder.st_rdev);
      result.guest_binder_private = result.guest_binder_rdev != result.host_binder_rdev;
      const int binder_fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
      if (binder_fd < 0) {
        result.guest_binder_errno = errno;
      } else {
        struct stat opened {};
        result.guest_binder_opened = fstat(binder_fd, &opened) == 0 &&
                                     static_cast<unsigned long long>(opened.st_rdev) ==
                                         result.guest_binder_rdev;
        close(binder_fd);
      }
    }
  }

  unsigned long long host_property_dev = 0, host_property_ino = 0;
  struct stat property_area {};
  if (!env_number("SSAL_HOST_DIR_DEV", &host_property_dev) ||
      !env_number("SSAL_HOST_DIR_INO", &host_property_ino) ||
      stat(kPropertyDirectory, &property_area) != 0) {
    result.property_area_errno = errno == 0 ? EINVAL : errno;
  } else {
    result.guest_property_area_differs_host =
        static_cast<unsigned long long>(property_area.st_dev) != host_property_dev ||
        static_cast<unsigned long long>(property_area.st_ino) != host_property_ino;
  }
  struct stat property_socket {};
  result.guest_property_socket_absent =
      lstat("/dev/socket/property_service", &property_socket) != 0 && errno == ENOENT;
  result.property_socket_errno = result.guest_property_socket_absent ? ENOENT : errno;
  return result;
}

bool path_resolution_errno(int error) {
  return error == ENOENT || error == ENOTDIR || error == ELOOP;
}

void log_proc_probe(const ProcPathResult& result, const char* actual_sid) {
  constexpr int kFlags = O_RDONLY | O_CLOEXEC;
  fprintf(stderr,
          "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
          "syscall=openat dirfd=%d flags=O_RDONLY|O_CLOEXEC(0x%x) errno=%d result=%s\n",
          getpid(), syscall(SYS_gettid), actual_sid, result.path, AT_FDCWD,
          static_cast<unsigned int>(kFlags), result.open_errno,
          result.open_succeeded ? "ok" : "failed");
  if (result.open_succeeded) {
    fprintf(stderr,
            "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
            "syscall=read fd_result=%s errno=%d\n",
            getpid(), syscall(SYS_gettid), actual_sid, result.path,
            result.read_succeeded ? "ok" : "failed", result.read_errno);
    fprintf(stderr,
            "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
            "syscall=close fd_result=%s errno=%d\n",
            getpid(), syscall(SYS_gettid), actual_sid, result.path,
            result.close_errno == 0 ? "ok" : "failed", result.close_errno);
  } else {
    fprintf(stderr,
            "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
            "syscall=read result=not_attempted errno=none\n",
            getpid(), syscall(SYS_gettid), actual_sid, result.path);
    fprintf(stderr,
            "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
            "syscall=close result=not_attempted errno=none\n",
            getpid(), syscall(SYS_gettid), actual_sid, result.path);
  }
}

bool proc_only_probe() {
  const pid_t pid = getpid();
  const long tid = syscall(SYS_gettid);
  char task_path[128];
  snprintf(task_path, sizeof(task_path), "/proc/self/task/%ld/attr/current", tid);
  ProcPathResult paths[] = {
      {"/proc/thread-self/attr/current"},
      {"/proc/self/attr/current"},
      {task_path},
  };
  for (ProcPathResult& result : paths) probe_proc_path(&result);

  char task_dir[96];
  char task_attr[112];
  snprintf(task_dir, sizeof(task_dir), "/proc/self/task/%ld", tid);
  snprintf(task_attr, sizeof(task_attr), "/proc/self/task/%ld/attr", tid);
  ProcComponentResult components[] = {
      {"/proc"},
      {"/proc/thread-self"},
      {"/proc/thread-self/attr"},
      {"/proc/thread-self/attr/current"},
      {"/proc/self"},
      {"/proc/self/attr"},
      {"/proc/self/attr/current"},
      {"/proc/self/task"},
      {task_dir},
      {task_attr},
      {task_path},
  };
  for (size_t i = 0; i < sizeof(components) / sizeof(components[0]); ++i) {
    const bool is_symlink = strcmp(components[i].path, "/proc/thread-self") == 0 ||
                            strcmp(components[i].path, "/proc/self") == 0;
    probe_proc_component(&components[i], is_symlink);
  }
  HostProcBoundary host_paths[16] = {};
  size_t host_path_count = 0;
  const bool host_paths_valid = probe_host_proc_boundaries(
      host_paths, sizeof(host_paths) / sizeof(host_paths[0]), &host_path_count);
  const GuestRuntimeBoundary runtime = probe_guest_runtime_boundaries();

  char actual_sid[256] = "unavailable";
  for (const ProcPathResult& result : paths) {
    if (result.read_succeeded && result.value[0] != '\0') {
      snprintf(actual_sid, sizeof(actual_sid), "%s", result.value);
      break;
    }
  }
  current_context = strcmp(actual_sid, "unavailable") == 0 ? nullptr : actual_sid;
  for (const ProcPathResult& result : paths) log_proc_probe(result, actual_sid);

  bool path_failure = (!paths[0].open_succeeded && path_resolution_errno(paths[0].open_errno)) ||
                      (!paths[0].read_succeeded && paths[0].read_errno >= 0 &&
                       path_resolution_errno(paths[0].read_errno));
  for (size_t i = 0; i < 4; ++i) {
    const ProcComponentResult& component = components[i];
    path_failure |= !component.stat_succeeded && path_resolution_errno(component.stat_errno);
    path_failure |= component.readlink_attempted && !component.readlink_succeeded &&
                    path_resolution_errno(component.readlink_errno);
  }
  for (const ProcComponentResult& component : components) {
    fprintf(stderr,
            "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
            "syscall=stat errno=%d result=%s mode=0%o uid=%u gid=%u\n",
            pid, tid, actual_sid, component.path, component.stat_errno,
            component.stat_succeeded ? "ok" : "failed", component.mode,
            component.uid, component.gid);
    if (component.readlink_attempted) {
      fprintf(stderr,
              "stage=guest_proc_probe pid=%d tid=%ld actual_sid=%s requested_path=%s "
              "syscall=readlink errno=%d result=%s target=%s\n",
              pid, tid, actual_sid, component.path, component.readlink_errno,
              component.readlink_succeeded ? "ok" : "failed",
              component.readlink_succeeded ? component.target : "");
    }
  }

  printf("{\"protocol\":1,\"pid\":%d,\"context\":", pid);
  json_string(actual_sid);
  printf(",\"executable_dev\":0,\"executable_ino\":0,\"proc_only\":{"
         "\"status\":\"%s\",\"tid\":%ld,\"actual_sid\":",
         host_paths_valid ? "complete" : "incomplete", tid);
  json_string(actual_sid);
  printf(",\"first_open_errno\":%d,\"path_resolution_failure\":%s,"
         "\"failure_class\":\"%s\",\"results\":[",
         paths[0].open_errno, path_failure ? "true" : "false",
         path_failure ? "PATH_RESOLUTION_FAILURE" : "UNDETERMINED");
  for (size_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    if (i != 0) putchar(',');
    printf("{\"requested_path\":");
    json_string(paths[i].path);
    printf(",\"open_errno\":%d,\"open_succeeded\":%s,\"read_errno\":%d,"
           "\"read_succeeded\":%s,\"close_errno\":%d,\"close_attempted\":%s,"
           "\"value\":",
           paths[i].open_errno, paths[i].open_succeeded ? "true" : "false",
           paths[i].read_errno, paths[i].read_succeeded ? "true" : "false",
           paths[i].close_errno, paths[i].close_attempted ? "true" : "false");
    json_string(paths[i].value);
    putchar('}');
  }
  printf("],\"components\":[");
  for (size_t i = 0; i < sizeof(components) / sizeof(components[0]); ++i) {
    if (i != 0) putchar(',');
    printf("{\"requested_path\":");
    json_string(components[i].path);
    printf(",\"stat_errno\":%d,\"stat_succeeded\":%s,\"mode\":%u,"
           "\"uid\":%u,\"gid\":%u,\"readlink_errno\":%d,"
           "\"readlink_attempted\":%s,\"readlink_succeeded\":%s,\"target\":",
           components[i].stat_errno, components[i].stat_succeeded ? "true" : "false",
           components[i].mode, components[i].uid, components[i].gid,
           components[i].readlink_errno,
           components[i].readlink_attempted ? "true" : "false",
           components[i].readlink_succeeded ? "true" : "false");
    json_string(components[i].target);
    putchar('}');
  }
  printf("],\"host_paths\":[");
  for (size_t i = 0; i < host_path_count; ++i) {
    if (i != 0) putchar(',');
    const HostProcBoundary& result = host_paths[i];
    printf("{\"pid\":%u,\"root_open_errno\":%d,\"root_opened\":%s,"
           "\"fd_dir_open_errno\":%d,\"fd_dir_opened\":%s,"
           "\"fd_read_errno\":%d,\"fd_read_succeeded\":%s,"
           "\"signal_zero_errno\":%d,\"signal_zero_allowed\":%s}",
           result.pid, result.root_open_errno, result.root_opened ? "true" : "false",
           result.fd_dir_open_errno, result.fd_dir_opened ? "true" : "false",
           result.fd_read_errno, result.fd_read_succeeded ? "true" : "false",
           result.signal_zero_errno, result.signal_zero_allowed ? "true" : "false");
  }
  printf("],\"runtime\":{\"guest_data\":{\"dev\":%llu,\"ino\":%llu,"
         "\"matches_profile\":%s,\"differs_host_data\":%s,\"write_read_unlink\":%s,\"errno\":%d},"
         "\"guest_binder\":{\"rdev\":%llu,\"host_rdev\":%llu,\"private\":%s,\"opened\":%s,\"errno\":%d},"
         "\"guest_property_area_differs_host\":%s,\"guest_property_socket_absent\":%s,"
         "\"property_area_errno\":%d,\"property_socket_errno\":%d}}}\n",
         runtime.guest_data_dev, runtime.guest_data_ino,
         runtime.guest_data_matches_profile ? "true" : "false",
         runtime.guest_data_differs_host ? "true" : "false",
         runtime.guest_data_write_read_unlink ? "true" : "false", runtime.guest_data_errno,
         runtime.guest_binder_rdev, runtime.host_binder_rdev,
         runtime.guest_binder_private ? "true" : "false",
         runtime.guest_binder_opened ? "true" : "false", runtime.guest_binder_errno,
         runtime.guest_property_area_differs_host ? "true" : "false",
         runtime.guest_property_socket_absent ? "true" : "false",
         runtime.property_area_errno, runtime.property_socket_errno);
  return true;
}

void mark_main_entry() {
  const char* value = getenv("SSAL_STAGE_FD");
  if (value == nullptr) return;
  const int fd = atoi(value);
  if (fd < 0) return;
  struct TraceEvent {
    uint32_t stage;
    int32_t error;
  } event = {10, 0};
  (void)write(fd, &event, sizeof(event));
}

void report(const Identity& identity, const Evidence& evidence) {
  printf(
      "{\"protocol\":1,\"pid\":%u,\"context\":\"%s\",\"executable_dev\":%llu,"
      "\"executable_ino\":%llu,\"property_area_live_poc\":{\"status\":\"%s\","
      "\"operation\":\"%s\",\"errno\":%d,\"mount_namespace_before\":\"%s\","
      "\"mount_namespace_after\":\"%s\",\"host_dir_dev\":%llu,\"host_dir_ino\":%llu,"
      "\"host_mount_id\":%d,\"guest_mount_id\":%d,\"area_dev\":%llu,\"area_ino\":%llu,"
      "\"area_size\":%llu,\"area_mount_id\":%d,\"property_label\":\"%s\","
      "\"property\":\"%s\",\"fsetxattr_attempted\":%s,\"fsetxattr_succeeded\":%s,"
      "\"fsetxattr_errno\":%d,\"writer_mapped\":%s,\"property_added\":%s,"
      "\"reader_mapped\":%s,\"property_found\":%s,\"readonly_value_match\":%s,"
      "\"host_area_separated\":%s,"
      "\"value\":\"%s\",\"separate_mapping\":%s,"
      "\"cleanup\":\"%s\"}}\n",
      static_cast<unsigned int>(getpid()), identity.context, identity.executable_dev,
      identity.executable_ino, evidence.status,
      evidence.operation == nullptr ? "none" : evidence.operation, evidence.error,
      evidence.mount_namespace_before, evidence.mount_namespace_after, evidence.host_dir_dev,
      evidence.host_dir_ino, evidence.host_mount_id, evidence.guest_mount_id, evidence.area_dev,
      evidence.area_ino, evidence.area_size, evidence.area_mount_id, evidence.property_label,
      kPropertyName, evidence.fsetxattr_attempted ? "true" : "false",
      evidence.fsetxattr_succeeded ? "true" : "false", evidence.fsetxattr_errno,
      evidence.writer_mapped ? "true" : "false", evidence.property_added ? "true" : "false",
      evidence.reader_mapped ? "true" : "false", evidence.property_found ? "true" : "false",
      evidence.readonly_value_match ? "true" : "false",
      evidence.host_area_separated ? "true" : "false",
      evidence.status[0] == 'p' ? kPropertyValue : "", evidence.separate_mapping ? "true" : "false",
      evidence.cleanup);
}

bool fail(Evidence* evidence, const char* operation, int error) {
  if (evidence->operation == nullptr) {
    evidence->operation = operation;
    evidence->error = error;
  }
  return false;
}

bool live_test(Evidence* evidence) {
  if (!copy_environment("SSAL_HOST_MNT_NS", evidence->mount_namespace_before,
                        sizeof(evidence->mount_namespace_before), evidence)) return false;
  if (!parse_environment_number("SSAL_HOST_DIR_DEV", &evidence->host_dir_dev, evidence) ||
      !parse_environment_number("SSAL_HOST_DIR_INO", &evidence->host_dir_ino, evidence)) return false;
  unsigned long long host_mount_id = 0;
  if (!parse_environment_number("SSAL_HOST_MOUNT_ID", &host_mount_id, evidence)) return false;
  if (host_mount_id == 0 || host_mount_id > 0x7fffffffULL) {
    return fail(evidence, "invalid_host_snapshot_environment");
  }
  evidence->host_mount_id = static_cast<int>(host_mount_id);
  if (!mount_namespace(evidence->mount_namespace_after,
                       sizeof(evidence->mount_namespace_after), evidence)) return false;
  if (strcmp(evidence->mount_namespace_before, evidence->mount_namespace_after) == 0) {
    return fail(evidence, "mount_namespace_not_separate");
  }
  evidence->cleanup = "namespace_teardown_after_child_exit";

  const int mount_fd = openat_diagnostic(
      AT_FDCWD, kPropertyDirectory, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC, 0,
      "live_test", "guest_property_mountpoint");
  if (mount_fd < 0) {
    remember_failure(evidence, "openat", errno);
    return false;
  }
  evidence->guest_mount_id = mount_id_for_fd(mount_fd, evidence);
  if (evidence->guest_mount_id < 0 ||
      evidence->guest_mount_id == evidence->host_mount_id) {
    close(mount_fd);
    return fail(evidence, "guest_mount_not_separate");
  }
  struct statfs root_filesystem {};
  if (fstatfs(mount_fd, &root_filesystem) != 0) {
    syscall_failure(evidence, "fstatfs");
    close(mount_fd);
    return false;
  }
  close(mount_fd);
  if (root_filesystem.f_type != kTmpfsMagic) return fail(evidence, "property_root_not_tmpfs");
  char root_label[sizeof(evidence->property_label)] = {};
  if (!file_label(kPropertyDirectory, root_label, sizeof(root_label), evidence)) return false;
  if (strcmp(root_label, kPropertyDirContext) != 0) {
    return fail(evidence, "unexpected_tmpfs_root_label");
  }
  // Parent validates the exact inherited FD set before resuming exec.
  struct stat preexisting_area {};
  if (fstatat(AT_FDCWD, kAreaPath, &preexisting_area, AT_SYMLINK_NOFOLLOW) == 0) {
    return fail(evidence, "property_area_path_not_fresh");
  }
  if (errno != ENOENT) {
    syscall_failure(evidence, "fstatat");
    return false;
  }

  AreaMappings mappings;
  bool label_failed = false;
  ssal_bionic_reset_failure();
  mappings.writer = prop_area::map_prop_area_rw(kAreaPath, kPropertyAreaContext, &label_failed);
  evidence->writer_mapped = mappings.writer != nullptr;
  evidence->fsetxattr_attempted = ssal_bionic_fsetxattr_attempted();
  evidence->fsetxattr_succeeded = ssal_bionic_fsetxattr_succeeded();
  evidence->fsetxattr_errno = ssal_bionic_fsetxattr_errno();
  if (mappings.writer == nullptr) {
    const char* operation = ssal_bionic_failure_operation();
    return fail(evidence, operation == nullptr ? "prop_area_map_rw" : operation,
                ssal_bionic_failure_errno());
  }
  if (label_failed) {
    return fail(evidence, "fsetxattr", ssal_bionic_failure_errno());
  }
  evidence->property_added = mappings.writer->add(kPropertyName, strlen(kPropertyName),
                                                   kPropertyValue, strlen(kPropertyValue));
  if (!evidence->property_added) {
    return fail(evidence, "prop_area_add");
  }

  ssal_bionic_reset_failure();
  mappings.reader = prop_area::map_prop_area(kAreaPath);
  if (mappings.reader == nullptr) {
    const char* operation = ssal_bionic_failure_operation();
    return fail(evidence, operation == nullptr ? "prop_area_map_read" : operation,
                ssal_bionic_failure_errno());
  }
  evidence->reader_mapped = true;
  evidence->separate_mapping = mappings.reader != mappings.writer;
  if (!evidence->separate_mapping) return fail(evidence, "separate_mmap_not_observed");
  const prop_info* property = mappings.reader->find(kPropertyName);
  evidence->property_found = property != nullptr;
  evidence->readonly_value_match =
      property != nullptr && strcmp(property->value, kPropertyValue) == 0;
  if (!evidence->readonly_value_match) {
    return fail(evidence, "prop_area_readback_mismatch");
  }

  mappings.area_fd = openat_diagnostic(AT_FDCWD, kAreaPath, O_RDONLY | O_CLOEXEC, 0,
                                       "live_test", "property_area_readback");
  if (mappings.area_fd < 0) {
    remember_failure(evidence, "openat", errno);
    return false;
  }
  struct stat area_info {};
  if (fstat(mappings.area_fd, &area_info) != 0) {
    syscall_failure(evidence, "fstat");
    return false;
  }
  struct statfs area_filesystem {};
  if (fstatfs(mappings.area_fd, &area_filesystem) != 0) {
    syscall_failure(evidence, "fstatfs");
    return false;
  }
  if (area_filesystem.f_type != kTmpfsMagic) return fail(evidence, "area_not_on_tmpfs");
  evidence->area_dev = static_cast<unsigned long long>(area_info.st_dev);
  evidence->area_ino = static_cast<unsigned long long>(area_info.st_ino);
  evidence->area_size = static_cast<unsigned long long>(area_info.st_size);
  if (evidence->area_size != kAreaSize) return fail(evidence, "property_area_size_mismatch");
  evidence->area_mount_id = mount_id_for_fd(mappings.area_fd, evidence);
  if (evidence->area_mount_id < 0 || evidence->area_mount_id != evidence->guest_mount_id) {
    return fail(evidence, "area_fd_mount_mismatch");
  }
  evidence->host_area_separated = evidence->area_mount_id != evidence->host_mount_id;
  if (!evidence->host_area_separated) return fail(evidence, "host_area_not_separated");
  const ssize_t label_size = fgetxattr(mappings.area_fd, "security.selinux",
                                       evidence->property_label,
                                       sizeof(evidence->property_label) - 1);
  if (label_size < 0) {
    syscall_failure(evidence, "fgetxattr");
    return false;
  }
  evidence->property_label[label_size] = '\0';
  if (strcmp(evidence->property_label, kPropertyAreaContext) != 0) {
    return fail(evidence, "property_area_label_mismatch");
  }
  mappings.close_all();
  // Parent rechecks the whitelist at PTRACE_EVENT_EXIT, before exit_files.
  evidence->status = "passed";
  return true;
}
}  // namespace

int main() {
  mark_main_entry();
  const char* proc_only = getenv("SSAL_PROC_ONLY");
  if (proc_only != nullptr && strcmp(proc_only, "1") == 0) {
    (void)proc_only_probe();
    return 0;
  }
  Identity identity;
  Evidence evidence;
  if (!current_identity(&identity, &evidence)) {
    report(identity, evidence);
    return 1;
  }
  const char* approved = getenv("SSAL_PROPERTY_AREA_APPROVED");
  if (approved == nullptr || strcmp(approved, "1") != 0) {
    if (strcmp(identity.context, kTarget) == 0) {
      evidence.operation = "approved_launcher_mode_required";
      report(identity, evidence);
      return 1;
    }
    evidence.status = "dry_run";
    report(identity, evidence);
    return 0;
  }
  if (strcmp(identity.context, kTarget) != 0) {
    evidence.operation = "wrong_selinux_context";
    report(identity, evidence);
    return 1;
  }
  evidence.cleanup = "namespace_teardown_unverified";
  char enforcing[16] = {};
  if (!read_text("/sys/fs/selinux/enforce", enforcing, sizeof(enforcing), &evidence,
                 "main", "global_enforcing") ||
      strcmp(enforcing, "1") != 0) {
    if (evidence.operation == nullptr) evidence.operation = "global_enforcing_required";
    report(identity, evidence);
    return 1;
  }
  if (geteuid() != 0) {
    evidence.operation = "root_credentials_required_for_tmpfs_area";
    report(identity, evidence);
    return 1;
  }
  const bool passed = live_test(&evidence);
  report(identity, evidence);
  return passed ? 0 : 1;
}

extern "C" const char* ssal_current_context() {
  return current_context == nullptr ? "unavailable" : current_context;
}
