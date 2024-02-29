from pwn import *
r = process('read Z; echo $Z', shell=True)
r.sendline(b'AAA')
r.interactive()
