; tolower: convert the single character in val1 to uppercase and store in val2
; ======
;       val1 @ 0x600000-600001
;       val2 @ 0x600001-600002
; ======
; Enter your codes: (type 'done:' when done)

mov ax, [0x600000]
and ax, 0xDF
; sub ax, 0x20
mov [0x600001], ax
done:

; 0x72 = 'r' -> 0x52 = 'R'
; 0x61 = 'a' -> 0x41 = 'A'
; 0111 0010 -> 0101 0010

; 0110 0001 -> 0100 0001

; *** FLAG: ASM{f5c7cf339d944fb779f1e87cfce4c86a7a79cfe6}