; swapreg: swap the values in RAX and RBX

mov rcx, rax
mov rax, rbx
mov rbx, rcx
done:


; *** FLAG: ASM{fd89f8b32b157f57b758f22f92f15f9b4f2d6ccd}