.set noreorder
.global __start
.global _start

__start:
_start:
    li $a0, 1
    la $a1, msg
    li $a2, 10
    li $v0, 4004
    syscall

    li $a0, 0
    li $v0, 4001
    syscall

msg:
    .ascii "mipsel-ok\n"
