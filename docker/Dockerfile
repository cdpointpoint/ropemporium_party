FROM debian:bookworm

ARG R2_VERSION=master

ENV DEBIAN_FRONTEND noninteractive
ENV TERM xterm-256color

ENV TZ Europe/Paris
ENV LANG fr_FR.UTF-8
ENV LANGUAGE fr_FR.UTF-8
ENV LC_ALL fr_FR.UTF-8

RUN apt update && apt-get install -y locales locales-all git gnupg colordiff colortail unzip vim tmux xterm \
    zsh curl telnet strace ltrace tmate less build-essential wget procps file \
    zstd net-tools bash-completion sudo gdb nasm pkgconf\
    libc6-i386 qemu-user libc6-armel-cross libc6-mipsel-cross gdb-multiarch 

RUN apt install -y python3 python3-pip python3-ropgadget python3-pwntools \
    python3-dev libssl-dev libffi-dev  
RUN apt-get remove --purge -y

# Set the locale
RUN locale-gen fr_FR.UTF-8  

RUN ln -s /usr/bin/python3 /usr/bin/python

# qemu post integration

RUN mkdir /etc/qemu-binfmt
RUN ln -s /usr/arm-linux-gnueabi /etc/qemu-binfmt/arm
RUN ln -s /usr/mipsel-linux-gnu /etc/qemu-binfmt/mipsel

# Build radare2
# RUN git clone https://github.com/radareorg/radare2
# RUN radare2/sys/install.sh
RUN mkdir -p /mnt && cd /mnt && \
  git clone -q -b "$R2_VERSION" --depth 100 https://github.com/radareorg/radare2.git && \
  cd radare2 && \
  ./configure --prefix=/usr && \
  make && \
  make symstall
    
# Create specific user
RUN adduser --quiet --disabled-password --uid 1000 --gecos "pts" --home /home/pts --shell=/bin/bash pts && \
    echo "pts:pts2025" | chpasswd
RUN usermod -aG sudo pts


RUN curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
# inhibe external package control on pip to avoid venv install of ropper
RUN echo "[global]" >/etc/pip.conf
RUN echo "break-system-packages = true" >>/etc/pip.conf
RUN pip install ropper

# Install GEF and patch blue color adresses
RUN wget -O /home/pts/.gdbinit-gef.py -q https://gef.blah.cat/py
RUN echo "set style address foreground cyan" >/home/pts/.gdbinit
RUN echo "set style disassembler immediate foreground cyan" >>/home/pts/.gdbinit
RUN echo 'source ~/.gdbinit-gef.py' >> /home/pts/.gdbinit
RUN echo 'theme registers_register_name cyan' >> /home/pts/.gdbinit

RUN ln -s /share /home/pts/challenges

RUN echo "set -g mouse on" >/home/pts/.tmux.conf

#RUN r2pm -U
#RUN r2pm -ci r2ghidra

COPY _vimrc /home/pts/.vimrc

RUN chown -R pts:pts /home/pts

WORKDIR /home/pts

USER  pts
CMD = ["/bin/bash"]

