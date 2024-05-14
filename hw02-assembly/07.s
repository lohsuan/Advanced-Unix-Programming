; isolatebit:
;         get the value bit-11 ~ bit-5 in AX and store the result in val1
;         (zero-based bit index)
; ======
;       val1 @ 0x600000-600001
;       val2 @ 0x600001-600002
; ======
; Enter your codes: (type 'done:' when done)

mov bl, [0x600001] ; store val2
shr ax, 5
and ax, 0x7F
mov [0x600000], ax
mov [0x600001], bl
done:

; FLAG: ASM{c83ee3bd4dfa3d5bf9c029de64dfcf3e796dba43}