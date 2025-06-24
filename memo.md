# Binary discovery

## security options

pwn checksec ret2win


## Liste sections details:

readelf -S callme --wide

rabin2 -S callme

radare2> iS

## used libraries

radare2> il

ldd callme

## imported functions

rabin2 -s callme|grep FUNC|grep imp


## Local functions

rabin2 -s callme|grep -e LOCAL|grep  FUNC

radare2>fs functions
fs

radare2>is

## memory segment

gdb> vnmap
