#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import base64
import zlib
import hashlib
import time
import sys
from pwn import *

def solve_pow(r):
    prefix = r.recvline().decode().split("'")[1];
    print(time.time(), "solving pow ...");
    solved = b''
    for i in range(1000000000):
        h = hashlib.sha1((prefix + str(i)).encode()).hexdigest();
        if h[:6] == '000000':
            solved = str(i).encode();
            print("solved =", solved);
            break;
    print(time.time(), "done.");
    r.sendlineafter(b'string S: ', base64.b64encode(solved));

if __name__ == "__main__":
    r = None
    if len(sys.argv) < 2:
        print(f'usage: {sys.argv[0]} libsolver.so [hostname]')
        sys.exit(-1)

    payload = None
    with open(sys.argv[1], 'rb') as f:
        payload = f.read()
        payload = zlib.compress(payload)
        payload = base64.b64encode(payload)
        print(f'## Payload loaded ({len(payload)} bytes), sha1 = {hashlib.sha1(payload).hexdigest()}')
    r = remote('up.zoolab.org' if len(sys.argv) == 2 else sys.argv[2], 10385)
    solve_pow(r);

    r.sendlineafter(b'payload: ', payload)

    r.interactive();
    r.close();

# vim: set tabstop=4 expandtab shiftwidth=4 softtabstop=4 number cindent fileencoding=utf-8 :
