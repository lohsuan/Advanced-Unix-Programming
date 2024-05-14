; loop15:
;         str1 is a string contains 15 lowercase and uppercase alphbets.
;         implement a loop to convert all alplabets to lowercase,
;         and store the result in str2.
; ======
;       str1 @ 0x600000-600010
;       str2 @ 0x600010-600020
; ======
; Enter your codes: (type 'done:' when done)

mov r8, 0
mov r9, 0x600000
mov r10, 0x600010

for_loop:
cmp r8, 15
jge finish

mov al, byte ptr [r9] ; al = str1[i]
or al, 0x20 ; al = tolower(str1[i])
next:
mov byte ptr [r10], al ; str2[i] = al
inc r8 ; i++
inc r9 ; str1++
inc r10 ; str2++
jmp for_loop
finish:

done:

; *** FLAG: ASM{4c4197f81627b0c5f442e4ddaebec65809071811}