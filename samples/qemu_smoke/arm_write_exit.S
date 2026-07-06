.syntax unified
.global _start

_start:
    mov r0, #1
    ldr r1, =msg
    mov r2, #7
    mov r7, #4
    svc #0

    mov r0, #0
    mov r7, #1
    svc #0

msg:
    .ascii "arm-ok\n"
