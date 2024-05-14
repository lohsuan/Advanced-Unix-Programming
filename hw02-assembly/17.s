; posneg: test if registers are positive or negative.
; if ( eax >= 0 ) { var1 = 1 } else { var1 = -1 }
; if ( ebx >= 0 ) { var2 = 1 } else { var2 = -1 }
; if ( ecx >= 0 ) { var3 = 1 } else { var3 = -1 }
; if ( edx >= 0 ) { var4 = 1 } else { var4 = -1 } 
; ======
;       var1 @ 0x600000-600004
;       var2 @ 0x600004-600008
;       var3 @ 0x600008-60000c
;       var4 @ 0x60000c-600010
; ======
; Enter your codes: (type 'done:' when done)


test eax, eax
jge positive_eax
mov dword ptr [0x600000], 0xffffffff
jmp next_eax
positive_eax:
mov dword ptr [0x600000], 1
next_eax:

test ebx, ebx
jge positive_ebx
mov dword ptr [0x600004], 0xffffffff
jmp next_ebx
positive_ebx:
mov dword ptr [0x600004], 1
next_ebx:

test ecx, ecx
jge positive_ecx
mov dword ptr [0x600008], 0xffffffff
jmp next_ecx
positive_ecx:
mov dword ptr [0x600008], 1
next_ecx:

test edx, edx
jge positive_edx
mov dword ptr [0x60000c], 0xffffffff
jmp next_edx
positive_edx:
mov dword ptr [0x60000c], 1
next_edx:

done:

; *** FLAG: ASM{b3e3824bdba8399815c106745dea10ef63ca83d8}