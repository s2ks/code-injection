	.globl	main
main:
	push    %rbp 		# save

	movq    %rsp, %rbp	# create new stack frame
	subq    $16, %rsp	# allocate 16 bytes

	movq    $1, %rax        # number for the 'write' system call
	movq    $1, %rdi        # stdout

	movq    $0x0a6f6c6c6548, %rsi	# "Hello\n"
	movq    %rsi, -8(%rbp)	# save on the stack
	leaq    -8(%rbp), %rsi	# pass address to 'write'

	movq    $6, %rdx        # write 6 bytes

	syscall

	movq    %rbp, %rsp	# free allocated memory
	pop     %rbp		# destroy stack frame

	int	$3		# break
