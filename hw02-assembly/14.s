; math5: 32-bit signed arithmetic
;         var3 = (var1 * -var2) / (var3 - ebx)
;         note: overflowed part should be truncated
; ======
;       var1 @ 0x600000-600004
;       var2 @ 0x600004-600008
;       var3 @ 0x600008-60000c
; ======
; Enter your codes: (type 'done:' when done)

mov eax, [0x600000]
imul eax, [0x600004]
neg eax
mov ecx, eax

mov eax, [0x600008]
sub eax, ebx

mov ebx, eax
mov eax, ecx
idiv ebx
mov [0x600008], eax
done:

; *** FLAG: ASM{1e130521b324b3009f4dd9dcc6a32eab9ce2d36f}