# https://youtu.be/9EcjWd-O4jI

FROM centos:centos6
MAINTAINER wireplay 

RUN yum -y update
RUN yum -y install http://dl.fedoraproject.org/pub/epel/6/x86_64/epel-release-6-8.noarch.rpm
RUN yum -y install httpd
RUN yum -y install git gcc
RUN yum -y install libpcap gcc libpcap-devel libnet libnet-devel ruby-devel ruby-libs

EXPOSE 60001

# startup script  
COPY run-httpd.sh /run-httpd.sh
COPY run-wireplay-server.sh /run-wireplay-server.sh
COPY bittorrent.stream36.pcap /wireplay/bittorrent.stream36.pcap
RUN chmod -v +x /run-httpd.sh
RUN chmod -v +x /run-wireplay-server.sh

RUN rm -rf /wireplay
RUN mkdir -p /wireplay
RUN git clone https://github.com/pmcgleenon/wireplay.git
RUN cd wireplay && make all

CMD ["/run-wireplay-server.sh"]
