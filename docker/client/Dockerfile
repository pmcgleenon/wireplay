# https://youtu.be/9EcjWd-O4jI

FROM centos:centos7
MAINTAINER wireplay 

RUN yum -y update
RUN yum -y install epel-release
RUN yum -y install httpd
RUN yum -y install git gcc
RUN yum -y install libpcap gcc libpcap-devel libnet libnet-devel 

# startup script  
COPY run-wireplay-client.sh /run-wireplay-client.sh
COPY bittorrent.stream36.pcap /wireplay/bittorrent.stream36.pcap
RUN chmod -v +x /run-wireplay-client.sh

RUN rm -rf /wireplay
RUN mkdir -p /wireplay
RUN git clone https://github.com/pmcgleenon/wireplay.git
RUN cd wireplay && make all

