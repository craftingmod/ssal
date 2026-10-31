#pragma once

// The live PoC records the failing kernel syscall directly in bionic_area.cpp.
#define ANDROID_LOG_ERROR 6
inline void async_safe_format_log(int, const char*, const char*, ...) {}
