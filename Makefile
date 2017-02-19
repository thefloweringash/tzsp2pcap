# Configurable variables
TARGET = tzsp2pcap
CFLAGS += -std=c99 -D_DEFAULT_SOURCE -Wall -Wextra -pedantic -O2 -g
LIBS = -lpcap
DESTDIR ?= /usr/local

tzsp2pcap: tzsp2pcap.c
	$(CC) -o $@ $(CFLAGS) $(LDFLAGS) $< $(LIBS)

.PHONY: clean all install uninstall

all: $(TARGET)

install: $(TARGET)
	install -s -m 755 $< $(DESTDIR)/bin

uninstall:
	rm -f $(DESTDIR)/bin/$(TARGET)

clean:
	rm -f $(TARGET)
