#include "property_label.h"

#include <cassert>

int main() {
  assert(expected_property_label(kPropertyAreaContext, sizeof(kPropertyAreaContext)));
  assert(expected_property_label(kPropertyAreaContext, sizeof(kPropertyAreaContext) - 1));
  assert(!expected_property_label("u:object_r:tmpfs:s0", sizeof("u:object_r:tmpfs:s0")));
  assert(!expected_property_label(kPropertyAreaContext, sizeof(kPropertyAreaContext) - 2));
  const char extra[] = "u:object_r:ssal_guest_property_area:s0x";
  assert(!expected_property_label(extra, sizeof(extra)));
}
