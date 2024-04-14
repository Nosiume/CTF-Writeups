FROM ubuntu:latest

WORKDIR /app

COPY src/. .

RUN apt-get update &&\
    apt-get install -y ucspi-tcp &&\
    rm -rf /var/lib/apt/lists/*


RUN chmod 100 pwn02
RUN chmod 400 flag.txt
RUN chmod 400 hvfstjehcy.txt

EXPOSE 13337

# Command to run tcpserver with the challenge
CMD ["tcpserver", "-v", "0.0.0.0", "13337", "./pwn02"]
