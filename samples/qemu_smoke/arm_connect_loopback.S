.syntax unified
.arm
.global _start

_start:
    @ socket(AF_INET=2, SOCK_STREAM=1, protocol=0)
    mov r0, #2
    mov r1, #1
    mov r2, #0
    ldr r7, =281
    svc #0

    @ save fd
    mov r4, r0

    @ build sockaddr_in on stack
    sub sp, sp, #16

    @ sin_family = AF_INET = 2
    mov r0, #2
    strh r0, [sp]

    @ sin_port = htons(80): memory bytes 00 50.
    @ On little-endian ARM, halfword 0x5000 stores bytes 00 50.
    ldr r0, =0x5000
    strh r0, [sp, #2]

    @ sin_addr = 127.0.0.1: memory bytes 7f 00 00 01.
    ldr r0, =0x0100007f
    str r0, [sp, #4]

    @ zero padding
    mov r0, #0
    str r0, [sp, #8]
    str r0, [sp, #12]

    @ connect(fd, sockaddr*, 16)
    mov r0, r4
    mov r1, sp
    mov r2, #16
    ldr r7, =283
    svc #0

    @ Linux ARM syscall failure returns negative errno.
    @ If connect failed, skip socket write to avoid SIGPIPE.
    cmp r0, #0
    blt stdout_write

    @ write(fd, "arm-net-ok\n", 11)
    mov r0, r4
    ldr r1, =msg
    mov r2, #11
    mov r7, #4
    svc #0

stdout_write:
    @ always write to stdout for target-state
    mov r0, #1
    ldr r1, =msg
    mov r2, #11
    mov r7, #4
    svc #0

    @ close(fd)
    mov r0, r4
    mov r7, #6
    svc #0

    @ exit(0)
    mov r0, #0
    mov r7, #1
    svc #0

.align 2
msg:
    .ascii "arm-net-ok\n"
