// Query selinuxfs only. No policy loading, domain transitions, mounts or services.
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void string(const char *s) {
    putchar('"');
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') printf("\\%c", c);
        else if (c < 32) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

static int read_text(const char *path, char *out, size_t size) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno;
    ssize_t n = read(fd, out, size - 1);
    int error = n < 0 ? errno : 0;
    close(fd);
    if (error) return error;
    out[n] = 0;
    while (n && (out[n - 1] == '\n' || out[n - 1] == '\r')) out[--n] = 0;
    return 0;
}

static void state(void) {
    char enforce[32] = "", version[32] = "", context[256] = "";
    int a = read_text("/sys/fs/selinux/enforce", enforce, sizeof(enforce));
    int b = read_text("/sys/fs/selinux/policyvers", version, sizeof(version));
    int c = read_text("/proc/self/attr/current", context, sizeof(context));
    char probe[16];
    int fd = open("/sys/fs/selinux/policy", O_RDONLY | O_CLOEXEC);
    int policy_error = fd < 0 ? errno : 0;
    if (fd >= 0) {
        if (read(fd, probe, sizeof(probe)) < 0) policy_error = errno;
        close(fd);
    }
    printf("{\"kind\":\"state\",\"enforce\":"); string(enforce);
    printf(",\"kernel_max_policy_version\":"); string(version);
    printf(",\"controller_context\":"); string(context);
    printf(",\"state_errno\":[%d,%d,%d],\"policy_read_errno\":%d}\n", a, b, c, policy_error);
}

static void context_query(const char *label) {
    int fd = open("/sys/fs/selinux/context", O_RDWR | O_CLOEXEC);
    int error = fd < 0 ? errno : 0;
    size_t length = strlen(label) + 1;
    if (fd >= 0) {
        ssize_t n = write(fd, label, length);
        error = n < 0 ? errno : ((size_t)n == length ? 0 : EIO);
        close(fd);
    }
    printf("{\"kind\":\"context\",\"label\":"); string(label);
    printf(",\"valid\":%s,\"errno\":%d}\n", error ? "false" : "true", error);
}

static void access_query(const char *source, const char *target, const char *class_name, const char *permission) {
    char path[256], text[128], request[2048], reply[256] = "";
    unsigned int index = 0, bit = 0, requested = 0;
    int error = 0;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", class_name);
    error = read_text(path, text, sizeof(text));
    if (!error) index = (unsigned int)strtoul(text, NULL, 10);
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/perms/%s", class_name, permission);
    if (!error) error = read_text(path, text, sizeof(text));
    if (!error) bit = (unsigned int)strtoul(text, NULL, 10);
    if (!error && (!index || bit < 1 || bit > 32)) error = EINVAL;
    if (!error) requested = UINT32_C(1) << (bit - 1);
    unsigned int allowed = 0, decided = 0, auditallow = 0, auditdeny = 0, sequence = 0, flags = 0;
    if (!error) {
        int fd = open("/sys/fs/selinux/access", O_RDWR | O_CLOEXEC);
        if (fd < 0) error = errno;
        else {
            int length = snprintf(request, sizeof(request), "%s %s %u %x", source, target, index, requested);
            if (length < 0 || (size_t)length >= sizeof(request)) error = EOVERFLOW;
            else {
                ssize_t n = write(fd, request, (size_t)length);
                if (n < 0) error = errno;
                else if (n != length) error = EIO;
                else {
                    n = read(fd, reply, sizeof(reply) - 1);
                    if (n < 0) error = errno;
                    else {
                        reply[n] = 0;
                        if (sscanf(reply, "%x %x %x %x %u %x", &allowed, &decided, &auditallow,
                                   &auditdeny, &sequence, &flags) != 6 || (decided & requested) != requested) error = EPROTO;
                    }
                }
            }
            close(fd);
        }
    }
    printf("{\"kind\":\"access\",\"source\":"); string(source);
    printf(",\"target\":"); string(target);
    printf(",\"class\":"); string(class_name);
    printf(",\"permission\":"); string(permission);
    printf(",\"errno\":%d,\"allowed\":", error);
    if (error) printf("null"); else printf("%s", (allowed & requested) == requested ? "true" : "false");
    printf(",\"requested_mask\":%u,\"allowed_mask\":%u,\"flags\":%u,\"sequence\":%u,\"raw_response\":",
           requested, allowed, flags, sequence);
    string(reply); puts("}");
}

static void validate_query(const char *source, const char *target, const char *task, const char *class_name) {
    char path[256], text[128], request[2048];
    unsigned int index = 0;
    int error = 0;
    snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", class_name);
    error = read_text(path, text, sizeof(text));
    if (!error) index = (unsigned int)strtoul(text, NULL, 10);
    if (!error && !index) error = EINVAL;
    if (!error) {
        int fd = open("/sys/fs/selinux/validatetrans", O_WRONLY | O_CLOEXEC);
        if (fd < 0) error = errno;
        else {
            int length = snprintf(request, sizeof(request), "%s %s %u %s", source, target, index, task);
            if (length < 0 || (size_t)length >= sizeof(request)) error = EOVERFLOW;
            else {
                ssize_t n = write(fd, request, (size_t)length);
                error = n < 0 ? errno : ((size_t)n == (size_t)length ? 0 : EIO);
            }
            close(fd);
        }
    }
    printf("{\"kind\":\"validatetrans\",\"source\":"); string(source);
    printf(",\"target\":"); string(target);
    printf(",\"task\":"); string(task);
    printf(",\"class\":"); string(class_name);
    printf(",\"valid\":%s,\"errno\":%d}\n", error ? "false" : "true", error);
}

int main(int argc, char **argv) {
    if (argc != 2 || geteuid() != 0) return 2;
    FILE *input = fopen(argv[1], "r");
    if (!input) return 3;
    state();
    char *line = NULL;
    size_t capacity = 0;
    int status = 0;
    while (getline(&line, &capacity, input) >= 0) {
        line[strcspn(line, "\r\n")] = 0;
        char *fields[6], *save = NULL;
        size_t count = 0;
        for (char *p = strtok_r(line, "\t", &save); p && count < 6; p = strtok_r(NULL, "\t", &save)) fields[count++] = p;
        if (count == 2 && !strcmp(fields[0], "C")) context_query(fields[1]);
        else if (count == 5 && !strcmp(fields[0], "A")) access_query(fields[1], fields[2], fields[3], fields[4]);
        else if (count == 5 && !strcmp(fields[0], "V")) validate_query(fields[1], fields[2], fields[3], fields[4]);
        else { status = 4; break; }
    }
    if (ferror(input)) status = 5;
    free(line);
    fclose(input);
    state();
    return ferror(stdout) ? 6 : status;
}
