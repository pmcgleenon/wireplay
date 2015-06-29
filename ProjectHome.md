# Wireplay #

A minimalist approach to replay pcap dumped TCP sessions with modification as required.

The aim of this project is to build an usable but simplistic tool which can help in selecting the TCP session to replay.  It can play both client as well as the server during a replay session.

Obviously replay attacks doesn't work against protocols which are cryptographically hardened or implements protocol specific replay prevention mechanism like challenge/response etc. Wireplay implements a plugin/hook subsystem mainly for the purpose of working around those replay prevention mechanism and also perform a certain degree of fuzz testing.

## Current Features ##

```
user@linux$ ./wireplay
Wireplay - The TCP Replay Tool v0.2

Options:
        -r       --role    [ROLE]       Specify the role to play (client/server)
        -F       --file    [FILE]       Specify the pcap dump file to read packets
        -t       --target  [TARGET]     Specify the target IP to connect to when in client role
        -p       --port    [PORT]       Specify the port to connect/listen
        -S       --shost   [SOURCE]     Specify the source host for session selection
        -D       --dhost   [DEST]       Specify the destination host for session selection
        -E       --sport   [SPORT]      Specify the source port for session selection
        -G       --dport   [DPORT]      Specify the destination port for session selection
        -n       --isn     [ISN]        Specify the TCP ISN for session selection
        -c       --count   [NUMBER]     Specify the number of times to repeat the replay
        -H       --hook    [FILE]       Specify the Ruby script to load as hook
        -L       --log                  Enable logging of data sent/receive
        -K       --disable-checksum     Disable NIDS TCP checksum verification
        -T       --timeout [MS]         Set socket read timeout in microsecond
        -Q       --simulate             Simulate Socket I/O only, do not send/recv


In case the --shost && --dhost && --isn && --sport && --dport parameters are not supplied,
the program will load all the TCP sessions from file and ask the user to select a session to replay
```

## Basic Usage ##

```
./wireplay -K --role client --port 80 --target 127.0.0.1 -L -F ./pcap/http.dump
```

The above runs wireplay with TCP checksum calculation disabled, replaying an
HTTP session from ./pcap/http.dump file.

```
./wireplay --role client -F ./pcap/dcedump.dump --target 172.16.34.129 --port 135
```

The above example reads a dcedump (Dave Aitel's dcedump) session from the file
dcedump.dump (pcap dump file) and replays it.

## What to do ? ##

  * Fuzzing for Security Bugs
  * General Software Testing
  * Being cool..
  * ??

## Ruby Hook Interface ##

First: In order to have a real life example of Wireplay hooking capability and
usage, take a look at hooks/rbhooks/cgen.rb

Wireplay implements a Ruby Interface for writing callback hooks. Hooks are called on occurrance of certain events like send-data, receive-data, error etc.

For a brief guide on writing Wireplay hooks in Ruby, read the [Wireplay Hook Guide](WireplayHooks.md)

## Compilation ##

Wireplay uses a modified version of [libnids](http://libnids.sf.net) library for TCP session reassembly from pcap frames. Read the [Compilation Guide](WireplayCompile.md) for some pointers.

## Field Testing ##

  * [Microsoft Terminal Server Fuzzing](MSRDPFuzzing.md)
  * [Microsoft RPC Interface Fuzzing](MSRPCFuzzing.md)

## Resources ##

  * Software Fuzzing with Wireplay ([NullCon](http://nullcon.net/), Goa 2010)
    * [Presentation](http://wireplay.googlecode.com/files/wireplay_nullcon_2010.pdf)
    * [Paper](http://wireplay.googlecode.com/files/wireplay_howto.pdf)

## TODO ##

  * Event Driven NIO model
  * Enhanced Hook Architecture
    * Handle SMB FID/UID update
    * Handle Token Changes in various Protocols
  * Libnids
    * Cleanup libnids to support delta delays
  * autotools based build/install scripts
  * Support for custom delay

## Acknowledgments ##

  * Jonathan Brossard (its your idea dude!)