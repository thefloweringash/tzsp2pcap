# tzsp2pcap

## Introduction
It is a simple utility to listen for [[http://en.wikipedia.org/wiki/TZSP][TaZmen Sniffer Protocol]] (TZSP)
packets and output the contents on stdout in pcap format. It has only
been lightly tested with Mikrotik RouterOS products, and may need
alterations to work with other devices.

## Installation
```
make && sudo make install
```

## Usage
Usage is simple:
```
tzsp2pcap [-h] [-v] [-f] [-p PORT] [-o FILENAME] [-s SIZE]
```

The -h flag shows the help for the utility.

The -v flag controls verbosity (repeat to increase up to -vv).

The -f flag forces output flush after every packet.

The -p flag lets you specify port to listen on (default is 37008).

The -o flag specifies path of output file (default is stdout)

The -s flag sets size of received buffer (default is 65535).

Example usage:
```
tzsp2pcap -f | wireshark -k -i -
```

## License
Copyright (c) 2012, Andrew Childs <lorne@cons.org.nz>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

 * Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the
   distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.