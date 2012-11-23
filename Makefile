CFLAGS += -Wall -Wextra

tzsp2pcap: tzsp2pcap.c
	cc -o $@ $(CFLAGS) $(LDFLAGS) -lpcap $<
