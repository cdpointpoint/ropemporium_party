;  nasm -felf64 bextr.asm && ld -o bextr bextr.o
          global    _start
          extern    printf

          section   .text

_start:   mov       rcx, 0x4847464544434241
          mov       rdx, 0x0000000000001008 ; 16:08
          bextr     rbx, rcx, rdx
          ;
          mov       rdi, buffer             ; save rbx to buffer
          mov       [rdi], ebx              ;
          mov       rax, 1                  ; sys_write
          mov       rsi, rdi                ; buffer
          mov       rdi, 1                  ; stdout
          mov       rdx, 17                 ; size
          syscall                           ; 
          mov       rax, 60                 ; system call for exit
          xor       rdi, rdi                ; exit code 0
          syscall                           ; invoke operating system to exit

          section   .data
buffer:   db        "               "       ; init white message (uggly)
          db        10      ; LF

