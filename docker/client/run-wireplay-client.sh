#!/bin/bash

# -p is the port number of the wireplay server 
exec /wireplay/wireplay -r server -F /wireplay/bittorrent.stream36.pcap -t 127.0.0.1 -p 49155 -K -c 1 -d 0
