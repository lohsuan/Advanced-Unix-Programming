; minicall: implement a minimal function call in the emulator
; ===== THE CODE
;     call   a
;     jmp    exit

; a:  ; function a - read ret-addr in rax
;     pop    rax
;     push   rax
;     ret
; exit:
; ======
; ======
; Enter your codes: (type 'done:' when done)

call    a
jmp    exit

a:
    pop    rax
    push   rax
    ret

exit:
done:

; ASM{a9e4d4a8f24efc2d1e8843e30408755e7727b488}