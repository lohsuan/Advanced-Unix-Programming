; dispbin:
;         given a number in AX, store the corresponding bit string in str1.
;         for example, if AX = 0x1234, the result should be:
;         str1 = 0001 0010 0011 0100
; ======
;       str1 @ 0x600000-600015
; ======


; void bit(int AX) {
;     int i;
;     for (i = 0; i < 16; i++) {
;         if (AX & 0x8000) {
;             str1[i] = '1';
;         } else {
;             str1[i] = '0';
;         }
;         AX = AX << 1;
;     }
;     str1[16] = '\0';
; }

mov bx, ax
mov r8, 0x600000
mov dx, 0 ; i = 0
mov si, 0x8000 ; mask = 0x8000

bit_loop:
    test bx, si ; if (AX & 0x8000)
    jz bit_zero ; else
    mov byte ptr [r8], '1'
    inc r8
    jmp bit_shift
bit_zero:
    mov byte ptr [r8], '0'
    inc r8
bit_shift:
    shl bx, 1  ; AX = AX << 1
    inc dx     ; i++
    cmp dx, 16 ; if (i < 16)
    jne bit_loop ; for loop

; mov byte ptr [r8], 0 ; str1[16] = '\0'
done:

; *** FLAG: ASM{c609df1bcca537262c0569ff1465831f6c77aeed}