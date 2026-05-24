FROM debian:trixie-slim

RUN apt update -y && apt install socat -y 

RUN useradd -m -s /bin/bash -u 666 ctf

WORKDIR /home/ctf/app
COPY ./meimei_quest .
COPY ./flag.txt .

RUN mkdir res
COPY ./res/meimei.txt ./res
COPY ./res/baobao.txt ./res

RUN chown root:root /home/ctf/app /home/ctf/app/flag.txt \
    && chmod 555 /home/ctf/app \
    && chmod 444 /home/ctf/app/flag.txt

USER ctf
EXPOSE 1337
CMD ["socat", "TCP-LISTEN:1337,reuseaddr,fork", "EXEC:./meimei_quest,stderr"]

