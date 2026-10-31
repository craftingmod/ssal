.section .text
.global _start
.type _start, %function
_start:
    mov x0, #1
    adrp x1, entry_marker
    add x1, x1, :lo12:entry_marker
    mov x2, #11
    mov x8, #64
    svc #0

    mov x0, #-100
    adrp x1, context_path
    add x1, x1, :lo12:context_path
    mov x2, #0
    mov x3, #0
    mov x8, #56
    svc #0
    cmp x0, #0
    b.lt fail
    mov x19, x0

    mov x0, x19
    adrp x1, context_buffer
    add x1, x1, :lo12:context_buffer
    mov x2, #128
    mov x8, #63
    svc #0
    cmp x0, #0
    b.le close_fail
    mov x20, x0

    mov x0, #1
    adrp x1, context_marker
    add x1, x1, :lo12:context_marker
    mov x2, #8
    mov x8, #64
    svc #0

    mov x0, #1
    adrp x1, context_buffer
    add x1, x1, :lo12:context_buffer
    mov x2, x20
    mov x8, #64
    svc #0

    mov x0, #1
    adrp x1, newline
    add x1, x1, :lo12:newline
    mov x2, #1
    mov x8, #64
    svc #0

    mov x0, x19
    mov x8, #57
    svc #0
    mov x0, #0
    b exit

close_fail:
    mov x0, x19
    mov x8, #57
    svc #0
fail:
    mov x0, #1
exit:
    mov x8, #94
    svc #0

.section .rodata
entry_marker:
    .ascii "BARE_ENTRY\n"
context_marker:
    .ascii "context="
newline:
    .ascii "\n"
context_path:
    .asciz "/proc/self/attr/current"

.section .bss
.balign 16
context_buffer:
    .skip 128

.section .note.GNU-stack,"",%progbits
