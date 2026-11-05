"""Guest-only, exact-binary experiment: compare current context before revalidating it."""
import hashlib
from pathlib import Path
import struct
import sys

source, destination = map(Path, sys.argv[1:])
if source.resolve() == destination.resolve():
    raise SystemExit("output must differ from the original Guest library")
data = bytearray(source.read_bytes())
if hashlib.sha256(data).hexdigest() != "9801ecf09ba52fcdd937b8195119996450628cf66e40b5896c1c5475411d3818":
    raise SystemExit("unsupported Guest libselinux input; no output written")
# The full input hash is checked below; this patch never changes a policy or a setter.
original = [0x97ffd98d, 0x37fffa40, 0xf94003e1, 0xaa1703e0, 0x940004c9, 0x340000c0]

def branch(pc, target):
    assert (target - pc) % 4 == 0
    return 0x94000000 | (((target - pc) // 4) & 0x3ffffff)

replacement = [
    0xf94003e1,                         # ldr x1, [sp] (original context)
    branch(0x16ac0, 0x17df0),           # strcmp(computed, original)
    0x34000000 | ((0x16ae8-0x16ac4)//4 << 5),  # cbz w0, success
    0xaa1703e0,                         # mov x0, x23 (computed context)
    branch(0x16acc, 0xd0f0),            # security_check_context
    0x37f80000 | (((0x16a08-0x16ad0)//4 & 0x3fff) << 5),  # tbnz w0,31,error
]
# ELF PT_LOAD maps this VA at the identical file offset in this one build.
assert list(struct.unpack_from('<6I', data, 0x16abc)) == original
struct.pack_into('<6I', data, 0x16abc, *replacement)
assert struct.unpack_from('<I', data, 0x16ad8)[0] == 0x94000632  # setcon unchanged
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_bytes(data)
print(f"input_sha256={hashlib.sha256(source.read_bytes()).hexdigest()}")
print(f"output_sha256={hashlib.sha256(data).hexdigest()}")
