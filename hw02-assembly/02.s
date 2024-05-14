; bubble: bubble sort for 10 integers
; ======
;       a[0] @ 0x600000-600004
;       a[1] @ 0x600004-600008
;       a[2] @ 0x600008-60000c
;       a[3] @ 0x60000c-600010
;       a[4] @ 0x600010-600014
;       a[5] @ 0x600014-600018
;       a[6] @ 0x600018-60001c
;       a[7] @ 0x60001c-600020
;       a[8] @ 0x600020-600024
;       a[9] @ 0x600024-600028
; ======
; Enter your codes: (type 'done:' when done)

; int bubble(int a[]) {
;     int i, j, temp;
;     for (i = 0; i < 9; i++) {
;         for (j = 0; j < 9; j++) {
;             if (a[j] > a[j+1]) {
;                 temp = a[j];
;                 a[j] = a[j+1];
;                 a[j+1] = temp;
;             }
;         }
;     }
;     return 0;
; }

_start:
    mov r8, 0x600000     ; r8 = &a[0]
    mov r9, 0            ; i = 0

for_i:
    mov r10, 0           ; j = 0
    cmp r9, 9
    jge finish           ; if i >= 9, exit loop

for_j:
    cmp r10, 9
    jge done_for_j       ; if j >= 9, exit loop

    mov eax, [r8 + r10*4]        ; a[j]
    mov ebx, [r8 + r10*4 + 4]    ; a[j+1]

    cmp eax, ebx
    jle skip_swap       ; if a[j] <= a[j+1], skip swap

    ; Swap a[j] and a[j+1]
    mov [r8 + r10*4], ebx      ; a[j] = a[j+1]
    mov [r8 + r10*4 + 4], eax  ; a[j+1] = a[j]

skip_swap:
    inc r10              ; j++
    jmp for_j

done_for_j:
    inc r9               ; i++
    jmp for_i

finish:
done:

; *** FLAG: ASM{e2899fc02f586c6e77a1b4262745f8b6c5fab572}