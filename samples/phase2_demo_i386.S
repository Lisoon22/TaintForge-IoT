.section .text
.global _start

.equ SYS_EXIT, 1
.equ SYS_WRITE, 4
.equ SYS_OPEN, 5
.equ SYS_CLOSE, 6
.equ SYS_SOCKETCALL, 102
.equ SYS_MPROTECT, 125

.equ O_RDONLY, 0
.equ PROT_READ_EXEC, 5
.equ AF_INET, 2
.equ SOCK_STREAM, 1
.equ SOCKETCALL_SOCKET, 1
.equ SOCKETCALL_CONNECT, 3
.equ SOCKETCALL_SEND, 9

_start:
    movl $_start, %ebx
    andl $-4096, %ebx
    subl $4096, %ebx
    movl $8192, %ecx
    movl $PROT_READ_EXEC, %edx
    movl $SYS_MPROTECT, %eax
    int $0x80

    movl $SYS_OPEN, %eax
    movl $required_file, %ebx
    movl $O_RDONLY, %ecx
    xorl %edx, %edx
    int $0x80
    testl %eax, %eax
    js file_missing

    movl %eax, %ebx
    movl $SYS_CLOSE, %eax
    int $0x80

    pushl $0
    pushl $SOCK_STREAM
    pushl $AF_INET
    movl %esp, %ecx
    movl $SOCKETCALL_SOCKET, %ebx
    movl $SYS_SOCKETCALL, %eax
    int $0x80
    addl $12, %esp
    testl %eax, %eax
    js network_unavailable
    movl %eax, %esi

    pushl $16
    pushl $remote_address
    pushl %esi
    movl %esp, %ecx
    movl $SOCKETCALL_CONNECT, %ebx
    movl $SYS_SOCKETCALL, %eax
    int $0x80
    addl $12, %esp
    testl %eax, %eax
    js close_network_failure

    pushl $0
    pushl $request_length
    pushl $request
    pushl %esi
    movl %esp, %ecx
    movl $SOCKETCALL_SEND, %ebx
    movl $SYS_SOCKETCALL, %eax
    int $0x80
    addl $16, %esp
    testl %eax, %eax
    js close_network_failure

    movl %esi, %ebx
    movl $SYS_CLOSE, %eax
    int $0x80

    movl $SYS_WRITE, %eax
    movl $1, %ebx
    movl $milestone, %ecx
    movl $milestone_length, %edx
    int $0x80

    xorl %ebx, %ebx
    movl $SYS_EXIT, %eax
    int $0x80

close_network_failure:
    movl %esi, %ebx
    movl $SYS_CLOSE, %eax
    int $0x80

network_unavailable:
    movl $SYS_WRITE, %eax
    movl $2, %ebx
    movl $network_error, %ecx
    movl $network_error_length, %edx
    int $0x80
    movl $20, %ebx
    movl $SYS_EXIT, %eax
    int $0x80

file_missing:
    movl $SYS_WRITE, %eax
    movl $2, %ebx
    movl $file_error, %ecx
    movl $file_error_length, %edx
    int $0x80
    movl $10, %ebx
    movl $SYS_EXIT, %eax
    int $0x80

.section .rodata
required_file:
    .asciz "/tmp/taintforge-phase2-demo.ready"

remote_address:
    .byte 2, 0
    .byte 0xbb, 0xe5
    .byte 198, 51, 100, 10
    .long 0
    .long 0

request:
    .ascii "HELLO"
.equ request_length, . - request

milestone:
    .ascii "TAINTFORGE_PHASE2_MILESTONE\n"
.equ milestone_length, . - milestone

file_error:
    .ascii "PHASE2_DEMO_FILE_MISSING\n"
.equ file_error_length, . - file_error

network_error:
    .ascii "PHASE2_DEMO_NETWORK_UNAVAILABLE\n"
.equ network_error_length, . - network_error
