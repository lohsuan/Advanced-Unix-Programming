#!/usr/bin/env python3
# -*- coding: utf-8 -*-
    
from pwn import *
import json

if __name__ == "__main__":

    r = remote('ipinfo.io', 80)
 
    # payload = b'GET / HTTP/1.1\r\nHost: ipinfo.io\r\nUser-Agent: curl/7.88.1\r\nAccept: */*\r\n\r\n'
    # r.send(payload)
 
    r.sendline(b'GET / HTTP/1.1')
    r.sendline(b'Host: ipinfo.io')
    r.sendline(b'User-Agent: curl/7.88.1')
    r.sendline(b'Accept: */*')
    r.sendline(b'')
    
    r.recvuntil(b'strict-transport-security: max-age=2592000; includeSubDomains\r\n')
    msg = r.recv()
    # print(msg.decode())
    
    data = json.loads(msg.decode()) # Decode the bytes to string and load it as JSON
    print(data['ip'])

    r.close()
        
