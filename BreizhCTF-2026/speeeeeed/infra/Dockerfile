FROM debian:trixie-slim

RUN apt update -y && apt install socat gcc -y

RUN useradd -m -s /bin/bash -u 666 ctf

WORKDIR /home/ctf/app

COPY ./speeeeeed .
COPY ./flag.c .

COPY ./run.sh .
COPY ./flag.txt .

RUN mkdir -p /var/www/html
COPY ./index.html /var/www/html
RUN chown -R ctf:ctf /var/www/html

RUN gcc flag.c -o getflag && chmod +s getflag && rm flag.c

RUN chown ctf:ctf /home/ctf/app \
    && chmod 777 /home/ctf/app \
    && chmod 400 /home/ctf/app/flag.txt

USER ctf
EXPOSE 1337
CMD ["bash", "run.sh"]



