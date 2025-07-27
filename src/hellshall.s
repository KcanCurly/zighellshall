    .data
wSystemCall:
    .long 0                # DWORD 0h
qSyscallInsAdress:
    .quad 0                # QWORD 0h

    .text
    .globl SetSSn
SetSSn:
    xorl    %eax, %eax
    movl    %eax, wSystemCall(%rip)
    movq    %rax, qSyscallInsAdress(%rip)
    movl    %ecx, %eax
    movl    %eax, wSystemCall(%rip)
    movq    %rdx, %r8
    movq    %r8, qSyscallInsAdress(%rip)
    ret

    .globl RunSyscall
RunSyscall:
    xorl    %r10d, %r10d
    movq    %rcx, %rax
    movq    %rax, %r10
    movl    wSystemCall(%rip), %eax
    jmp     *qSyscallInsAdress(%rip)
    # (code after jmp won't run)
