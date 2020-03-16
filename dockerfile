FROM ubuntu:19.10

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get -y install python3 python3-pip build-essential libpcap-dev openssl curl tcpdump net-tools default-jre
RUN pip3 install scapy

WORKDIR "/tmp"