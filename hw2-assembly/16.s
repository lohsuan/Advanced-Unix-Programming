; mulbyshift: multiply val1 by 26 and store the result in val2
; ======
;       val1 @ 0x600000-600004
;       val2 @ 0x600004-600008
; ======
; Enter your codes: (type 'done:' when done)

mov ebx, [0x600000]
shl ebx, 4
add eax, ebx
mov ebx, [0x600000]
shl ebx, 2
add eax, ebx
add eax, ebx
mov ebx, [0x600000]
shl ebx, 1
add eax, ebx
mov [0x600004], eax
done:

; 26 = 16 + 4 + 4 + 2

; *** FLAG: ASM{342e07fdef8fce60723fe57e8b6f2a2e38b9a3d5}