.section .text
.global _start
.type _start, %function
_start:
    mov x0, #42
    mov x8, #94
    svc #0

.section .note.GNU-stack,"",%progbits
