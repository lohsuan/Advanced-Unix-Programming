; eval1:
;         Rval = -Xval + (Yval - Zval)
; ======
;       Xval @ 0x600000-600004
;       Yval @ 0x600004-600008
;       Zval @ 0x600008-60000c
;       Rval @ 0x60000c-600010
; ======
; Enter your codes: (type 'done:' when done)

mov eax, [0x600000]
mov ebx, [0x600004]
mov ecx, [0x600008]
neg eax
sub ebx, ecx
add eax, ebx
mov [0x60000c], eax
done:

; *** FLAG: ASM{96495ea5d5873d06f7a629d7df04480506d1061c}