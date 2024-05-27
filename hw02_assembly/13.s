; math4: 32-bit signed arithmetic
;         var4 = (var1 * -5) / (-var2 % var3)
;         note: overflowed part should be truncated
; ======
;       var1 @ 0x600000-600004
;       var2 @ 0x600004-600008
;       var3 @ 0x600008-60000c
;       var4 @ 0x60000c-600010
; ======
; Enter your codes: (type 'done:' when done)


mov eax, [0x600004]
neg eax
mov ebx, [0x600008]
cdq
idiv ebx
mov ebx, edx

mov eax, [0x600000]
imul eax, -5
cdq
idiv ebx
mov [0x60000c], eax
done:


; *** FLAG: ASM{8bfd9c41bced0fa842f1e28049f286fa2edd9b88}