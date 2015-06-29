#Status

[![Build Status](https://travis-ci.org/pmcgleenon/wireplay.svg)](https://travis-ci.org/pmcgleenon/wireplay)

# Wireplay 

A minimalist approach to replay pcap dumped TCP sessions with modification as
required.

The aim of this project is to build an usable but simplistic tool which can help
in selecting the TCP session to replay. It can play both client as well as the
server during a replay session.

Obviously replay attacks doesn't work against protocols which are cryptographically
hardened or implements protocol specific replay preventation mechanism like
challenge/response etc. Wireplay implements a plugin/hook subsystem mainly for
the purpose of working around those replay prevention mechanism and also perform
a certain degree of fuzz testing.

It also won't work out of the box for certain non-deterministic sessions like
say:

## Original 

   C> GET /abc.tar.gz HTTP/1.1\r\n...
   S> HTTP 404 Not Found
   ...

## Replay 

   C> GET /abc.tar.gz HTTP/1.1\r\n..
   S> HTTP 200 Found

## Getting Started 

./wireplay -K --role client --port 80 --target 127.0.0.1 -L -F ./pcap/http.dump

The above runs wireplay with TCP checksum calculation disabled, replaying an
HTTP session from ./pcap/http.dump file.

./wireplay --role client -F ./pcap/dcedump.dump --target 172.16.34.129 --port 135

The above example reads a dcedump (Dave Aitel's dcedump) session from the file
dcedump.dump (pcap dump file) and replays it.

# What to do with it? 

   * Fuzzing for Security Bugs
	* General Software Testing
	* Being cool..

# Ruby Interface 

First: In order to have a real life example of Wireplay hooking capability and
usage, take a look at hooks/rbhooks/cgen.rb

Wireplay implements a Ruby Interface for writing hooks in Ruby. Hooks are called
before sending and after receiving data.

You can also register hook to be called on error.

Example:

   Hooks register a hook object containing callback methods which are called on
   occurrance of specific events like sending data, received data, error etc.

   Have a look at hooks/rbhooks/*.rb for an idea

# Notes 

   * libnids-1.23 had does not set certain pointers to NULL during nids_exit()
     and hence refers to invalid free'd memory during next nids_init() and tcp
     capture and crashes. The patched version of libnids in the $(pwd) needs to
     be used until it is fixed upstream.

   * TCP Checksum Offloading: Modern NIC hardwares support TCP/UDP checksum
     calculation in hardware. So OS Network Stack might write packets to NIC
     with incorrect/null checksum expecting the NIC to calculate and re-write
     appropriate checksum before xmit. As a result sniffed TCP packets might
     have incorrect checksums which won't be picked up by NIDS unless
     checksumming is disabled.

     For modern hardwares, its safe to run wireplay with -K to disabled NIDS
     checksuming by default.
