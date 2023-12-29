	.globl _start
_start:
	pushq 	%rbp
	movq	%rsp, %rbp

	subq	$16, %rsp

	# open syscall
	movq	$2, %rax

	movb	-16(%rbp), $0x2e # '.'
	movb	-15(%rbp), $0x2f # '/'
	movb	-14(%rbp), $0x70 # 'p'
	movb	-13(%rbp), $0x61 # 'a'
	movb	-12(%rbp), $0x79 # 'y'
	movb	-11(%rbp), $0x6c # 'l'
	movb	-10(%rbp), $0x6f # 'o'
	movb	-9(%rbp),  $0x61 # 'a'
	movb	-8(%rbp),  $0x64 # 'd'
	movb	-7(%rbp),  $0x2e # '.'
	movb	-6(%rbp),  $0x73 # 's'
	movb	-5(%rbp),  $0x6f # 'o'
	movb	-4(%rbp),  $0x00 # null

	# path
	leaq	-16(%rbp), %rdi

	# read only flag
	movq	$0, %rsi

	movq	%rbp, %rsp
	popq	%rbp

	ret




