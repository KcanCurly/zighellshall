    .data
wSystemCall:
    .long 0                # DWORD 0h
qSyscallInsAdress:
    .quad 0                # QWORD 0h

    .text
    .globl SetSSn
SetSSn:
    # xor eax, eax            # eax = 0
    xorl    %eax, %eax
    # mov wSystemCall, eax    # wSystemCall = 0
    movl    %eax, wSystemCall(%rip)
    # mov qSyscallInsAdress, rax # qSyscallInsAdress = 0
    movq    %rax, qSyscallInsAdress(%rip)
    # mov eax, ecx            # eax = ssn
    movl    %ecx, %eax
    # mov wSystemCall, eax    # wSystemCall = eax = ssn
    movl    %eax, wSystemCall(%rip)
    # mov r8, rdx             # r8 = AddressOfASyscallInst
    movq    %rdx, %r8
    # mov qSyscallInsAdress, r8 # qSyscallInsAdress = r8
    movq    %r8, qSyscallInsAdress(%rip)
    ret

    .globl RunSyscall
RunSyscall:
    # xor r10, r10           # r10 = 0
    xorl    %r10d, %r10d
    # mov rax, rcx           # rax = rcx
    movq    %rcx, %rax
    # mov r10, rax           # r10 = rax = rcx
    movq    %rax, %r10
    # mov eax, wSystemCall   # eax = ssn
    movl    wSystemCall(%rip), %eax
    # jmp qword ptr [qSyscallInsAdress]
    jmp     *qSyscallInsAdress(%rip)
    # (code after jmp won't run)
