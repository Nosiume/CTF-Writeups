FROM python:3.13.11
RUN useradd -m -s /bin/bash -u 666 ctf

WORKDIR /home/ctf/app

COPY ./chall.py .
COPY ./flag.c .
COPY ./cool_compress.so .

COPY ./run.sh .
COPY ./flag.txt .

RUN mkdir /opt/fsp
RUN chown ctf:ctf /opt/fsp

RUN gcc flag.c -o flag
RUN chmod +s flag

RUN chown ctf:ctf /home/ctf/app \
    && chmod 777 /home/ctf/app \
    && chmod 400 /home/ctf/app/flag.txt


USER ctf
EXPOSE 1337
CMD ["bash", "run.sh"]


