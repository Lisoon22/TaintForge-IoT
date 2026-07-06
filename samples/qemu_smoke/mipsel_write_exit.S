.set noreorder
.set noat
.text
.global __start
.global _start

__start:
_start:
    addiu $sp, $sp, -16

    # "mipsel-ok\n" stored directly on stack, little-endian.
    # bytes: 6d 69 70 73 65 6c 2d 6f 6b 0a
    li $t0, 0x7370696d
    sw $t0, 0($sp)

    li $t0, 0x6f2d6c65
    sw $t0, 4($sp)

    li $t0, 0x0a6b
    sh $t0, 8($sp)

    # write(1, sp, 10)
    li $a0, 1
    move $a1, $sp
    li $a2, 10
    li $v0, 4004
    syscall

    # exit(0)
    li $a0, 0
    li $v0, 4001
    syscall
