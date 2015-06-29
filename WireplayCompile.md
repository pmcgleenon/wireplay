# Wireplay Compilation Guide #

## Dependencies ##

  * [libpcap](http://www.tcpdump.org)
  * [Ruby 1.8.x](http://www.ruby-lang.org)
  * [libnet 1.x](http://??)

### Installation for Ubuntu/Debian ###

```
sudo apt-get install ruby1.8 ruby1.8-dev libruby1.8 \ 
libpcap0.8 libpcap0.8-dev libnet1 libnet1-dev
```

## Compile ##

Download and extract wireplay or checkout from svn:

By default Makefile will try to link against libnids-1.23 in the current directory because of the custom patches (bug fixes) in libnids.

So before you try to compile wireplay, you need to compile libnids: go to ./libnids-1.23:
```
   ./configure --enable-shared --disable-libglib
   make
```

Then go to wireplay root:
```
   make
```

In case compilation fails, try to tickle around with the variables in Makefile
or drop a bug report to AUTHORS

In case wireplay crashes everytime, most probably you are linked against system installed libnids, verify:
```
   ldd ./wireplay
```