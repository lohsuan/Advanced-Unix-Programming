; leax:
;         eax = edi * 2
;         ebx = edi * 3
;         ecx = edi * 5
;         edx = edi * 9
; ======
; ======
; Enter your codes: (type 'done:' when done)

lea eax, [edi * 2]
lea ebx, [edi * 2 + edi]
lea ecx, [edi * 4 + edi]
lea edx, [edi * 8 + edi]
done:

; *** FLAG: ASM{d12f094d5858d099f2cd2a0e5e1016bec766b9ab}