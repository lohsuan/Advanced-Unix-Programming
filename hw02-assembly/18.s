; recur: implement a recursive function

;    r(n) = 0, if n <= 0
;         = 1, if n == 1
;         = 2*r(n-1) + 3*r(n-2), otherwise
   
;    please call r(19) and store the result in RAX
; ======
; ======
; Enter your codes: (type 'done:' when done)

push    rbp
mov     rbp, rsp
sub     rsp, 16
mov     DWORD PTR [rbp-4], 30   ; r(30)
mov     eax, DWORD PTR [rbp-4]
mov     edi, eax
call    recur
jmp     finish

recur:
    push    rbp
    mov     rbp, rsp
    push    rbx
    sub     rsp, 24
    mov     DWORD PTR [rbp-20], edi ; n
    
    cmp     DWORD PTR [rbp-20], 0   ; if(n <= 0)
    jg      n_is_larger_than_0      ; n > 0
    mov     eax, 0                  ; return 0
    jmp     leave_stack         

n_is_larger_than_0:
    cmp     DWORD PTR [rbp-20], 1   ;if(n == 1)
    jne     n_is_not_equal_to_1     ; n != 1
    mov     eax, 1                  ; return 1
    jmp     leave_stack  

n_is_not_equal_to_1:
    mov     eax, DWORD PTR [rbp-20] ; eax = n
    sub     eax, 1                  ; eax = n - 1
    mov     edi, eax                ; edi = n - 1
    call    recur                   ; r(n-1)
    lea     rbx, [rax+rax]          ; 2*r(n-1)

    mov     eax, DWORD PTR [rbp-20] ; n
    sub     eax, 2                  ; n - 2
    mov     edi, eax                ; edi = n - 2
    call    recur                   ; r(n-2)

    mov     rdx, rax                ; rdx= r(n-2)
    mov     rax, rdx                ; rax = r(n-2)
    add     rax, rax                ; rax = 2*r(n-2)
    add     rax, rdx                ; rax = 3*r(n-2)
    add     rax, rbx                ; rax = 2*r(n-1) + 3*r(n-2)
leave_stack:
    mov     rbx, QWORD PTR [rbp-8]
    leave
    ret
finish:
done:

; FLAG: ASM{248c68348d3c0c6ff259dc6d12081949d61ae82c}

; C code for the assembly code above
; long long recur(int n) {
;     if (n <= 0) {
;         return 0;
;     } else if (n == 1) {
;         return 1;
;     } 
;     return 2 * recur(n - 1) + 3 * recur(n - 2);
; }

; int main() {
;     int n = 19;
;     long long result = recur(n);
;     return 0;
; }