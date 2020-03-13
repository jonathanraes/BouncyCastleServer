FROM ubuntu:19.10

RUN apt-get update
RUN apt-get -y install python3 python3-pip build-essential libpcap-dev openssl curl default-jre

WORKDIR "/tmp"