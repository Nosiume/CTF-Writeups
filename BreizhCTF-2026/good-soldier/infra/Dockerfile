FROM debian:trixie-slim

RUN apt update -y && apt install socat -y 

RUN useradd -m -s /bin/bash ctf

WORKDIR /home/ctf/app
COPY ./good_soldier .
COPY ./libc.so.6 .
COPY ./ld-linux-x86-64.so.2 .
COPY ./flag.txt /

RUN mkdir res
COPY ./res/ascii_knight.txt ./res
COPY ./res/grim_reaper.txt ./res
COPY ./res/monster.txt ./res
COPY ./res/zombie.txt ./res

RUN chown root:root /home/ctf/app /flag.txt \
    && chmod 555 /home/ctf/app \
    && chmod 444 /flag.txt

USER ctf
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./good_soldier,stderr"]

