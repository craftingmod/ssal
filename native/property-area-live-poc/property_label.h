#pragma once

#include <cstddef>
#include <cstring>

constexpr char kPropertyAreaContext[] = "u:object_r:ssal_guest_property_area:s0";

inline bool expected_property_label(const char* label, size_t size) {
  constexpr size_t length = sizeof(kPropertyAreaContext) - 1;
  return (size == length || (size == length + 1 && label[length] == '\0')) &&
         memcmp(label, kPropertyAreaContext, length) == 0;
}
