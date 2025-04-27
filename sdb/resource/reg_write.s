    .global main
    .section .data
    .section .text

.macro trap
    movq $62, %rax
    movq %r12, %rdi
    movq $5, %rsi
    syscall
.endm

main:
    push %rbp
    movq %rsp, %rbp

    # Get pid
    movq $39, %rax
    syscall
    movq %rax, %r12

    trap

    popq %rbp
    movq $0, %rax
    ret