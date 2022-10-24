FROM ubuntu:latest
ENV user=hw0
RUN apt-get update
RUN apt-get install -y gcc make
RUN useradd -m $user
COPY code/ /home/$user/code
WORKDIR /home/$user/code
RUN make clean
RUN make
EXPOSE 1234
ENTRYPOINT ["./hw0"]
