#include <android/log.h>
void __android_log_write_log_message(struct __android_log_message* message) {
    __android_log_stderr_logger(message);
}
void __android_log_logd_logger(const struct __android_log_message* message) {
    __android_log_stderr_logger(message);
}
// Keep Android daemon/compiler diagnostics in the session pipes, away from Host logd.
__attribute__((constructor)) static void session_logger(void) {
    __android_log_set_logger(__android_log_stderr_logger);
    __android_log_set_minimum_priority(ANDROID_LOG_VERBOSE);
}
