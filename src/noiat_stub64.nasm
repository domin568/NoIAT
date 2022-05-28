bits 64
section .text

global stub64
stub64:
	xor eax, eax
	nop
	nop
	xchg edx,eax
	ret