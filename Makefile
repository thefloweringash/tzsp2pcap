# Configurable variables
CFLAGS = -Wall -Wextra -pedantic -O2

tzsp2pcap: tzsp2pcap.c
	cc -std=c99 -o $@ $(CFLAGS) $(LDFLAGS) -lpcap $<

.PHONY: clean all

all: tzsp2pcap

clean:
	rm -f tzsp2pcap
