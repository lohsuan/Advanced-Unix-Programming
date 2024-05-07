; math2: signed arithmetic
; 	eax = (-var1 * var2) + var3
; ======
;       var1 @ 0x600000-600004
;       var2 @ 0x600004-600008
;       var3 @ 0x600008-60000c
; ======
; Enter your codes: (type 'done:' when done)

mov eax, [0x600000]
neg eax
imul eax, [0x600004]
add eax, [0x600008]
done:

FLAG: ASM{9534f42b2762f41d4b4c4b9b945f9995f067734b}