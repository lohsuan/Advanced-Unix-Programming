#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import time
from pwn import *
import re
import base64

zero = '''
┌───┐
│   │
│   │
│   │
└───┘'''.splitlines()[1:]

one = '''
 ─┐  
  │  
  │  
  │  
 ─┴─ '''.splitlines()[1:]

two = '''
┌───┐
    │
┌───┘
│    
└───┘'''.splitlines()[1:]

three = '''
┌───┐
    │
 ───┤
    │
└───┘'''.splitlines()[1:]

four = '''
│   │
│   │
└───┤
    │
    │'''.splitlines()[1:]

five = '''
┌────
│    
└───┐
    │
└───┘'''.splitlines()[1:]

six = '''
┌───┐
│    
├───┐
│   │
└───┘'''.splitlines()[1:]

seven = '''
┌───┐
│   │
    │
    │
    │'''.splitlines()[1:]

eight = '''
┌───┐
│   │
├───┤
│   │
└───┘'''.splitlines()[1:]

nine = '''
┌───┐
│   │
└───┤
    │
└───┘'''.splitlines()[1:]

digit_mapping = {
    '0': zero,
    '1': one,
    '2': two,
    '3': three,
    '4': four,
    '5': five,
    '6': six,
    '7': seven,
    '8': eight,
    '9': nine
}

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

def token_to_num_int(token):
  num = '-1'
  for key, value in digit_mapping.items():
    same = True
    for i in range(5):
      for j in range(5):
          if (value[i][j] != token[i][j]):
              same = False

    if same == True:
      num = key
      break
#   print(num)
  return int(num)

def determine_operation(image_to_compute):
  operation = ''
  if ('┼' in image_to_compute):
      operation = '+'
  elif ('╳' in image_to_compute):
      operation = '*'
  else:
      operation = '//'
  return operation


def image_to_answer(image_to_compute):
    splitline_image = image_to_compute.split('\n')
    operation = determine_operation(image_to_compute)
    
    a, b = 0, 0
    a_list = [1, 8, 15] if operation != '//' else [1, 8, 15, 22]
    b_list = [29, 36, 43] if operation != '//' else [36, 43]

    token = [ ['x']*5 for i in range(5)]

    for leading_space in a_list:
        for i in range(5):
            for j in range(5):
                token[i][j] = splitline_image[i][j+leading_space]
            
        a = a*10 + token_to_num_int(token)

    for leading_space in b_list:
        for i in range(5):
            for j in range(5):
                token[i][j] = splitline_image[i][j+leading_space]
        
        b = b*10 + token_to_num_int(token)
    
    print(a, operation, b)
    
    ans = 0
    if operation == '+':
        ans = a + b
    elif operation == '*':
        ans = a * b
    else:
        ans = a // b
    
    return ans


if __name__ == "__main__":
    r = remote('up.zoolab.org', 10681)
    solve_pow(r)
    r.recvuntil(b'Welcome to the INTEGER arithmetic 2D challenge')
    message = r.recvuntil(b'challenges in a limited time.').decode()
    
    challenge_count = int(message.split(' ')[3])
    print(challenge_count)
    
    for count in range(challenge_count):
        r.recvuntil(b': ')
        b64 = r.recvuntil(b' = ?')[:-4].decode()
        # print(b64)
        image_to_compute = base64.b64decode(b64).decode()
        print(image_to_compute)
        
        ans = image_to_answer(image_to_compute)
        r.send(str(ans).encode() + b"\r\n")
        
    r.interactive()

#  ┌───┐  ┌───┐  ┌───┐         ┌────  ┌────  ┌───┐
#  │   │      │  │   │   ╲ ╱   │      │      │   │
#  ├───┤   ───┤      │    ╳    └───┐  └───┐  └───┤
#  │   │      │      │   ╱ ╲       │      │      │
#  └───┘  └───┘      │         └───┘  └───┘  └───┘

#  ┌───┐  ┌────  ┌───┐         │   │  ┌────  │   │
#      │  │      │        │    │   │  │      │   │
#   ───┤  └───┐  ├───┐  ──┼──  └───┤  └───┐  └───┤
#      │      │  │   │    │        │      │      │
#  └───┘  └───┘  └───┘             │  └───┘      │

#  ┌───┐  ┌───┐  ┌───┐  ┌───┐         ┌───┐  ┌───┐ 
#  │   │      │      │  │   │    •    │      │   │ 
#  ├───┤   ───┤   ───┤  └───┤  ─────  ├───┐      │ 
#  │   │      │      │      │    •    │   │      │ 
#  └───┘  └───┘  └───┘  └───┘         └───┘      │ 
