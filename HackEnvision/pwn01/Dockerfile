FROM ubuntu:latest

WORKDIR /app

COPY src/. .

RUN apt-get update && \
    apt-get install -y ucspi-tcp && \
    rm -rf /var/lib/apt/lists/*


RUN chmod 100 pwn01
RUN chmod 400 flag.txt

EXPOSE 1337

CMD ["tcpserver", "-v", "0.0.0.0", "1337", "./pwn01"]
