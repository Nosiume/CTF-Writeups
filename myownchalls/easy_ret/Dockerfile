FROM archlinux:latest

RUN pacman -Syyu --noconfirm

RUN useradd -d /home/chall -m -p ctf -s /bin/bash chall
RUN echo "chall:chall" | chpasswd

WORKDIR /home/chall

COPY chall .
COPY ynetd .
COPY flag.txt .

USER chall
EXPOSE 9000
CMD ./ynetd -p 9000 ./chall