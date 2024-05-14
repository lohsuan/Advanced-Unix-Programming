
; clear17: clear bit-17 in eax (zero-based index)
; Enter your codes: (type 'done:' when done)

; void clear17(int *a) {
;     *a &= ~(1 << 17);
; }

and eax, 0xfffdffff
done:

; 1111 -> f
; 1110 -> e
; 1101 -> d

; *** FLAG 2503: ASM{b5fe87b2c36a2cfd45bf7fe4a8311752e50d3115}
