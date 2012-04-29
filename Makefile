tzsp2pcap: tzsp2pcap.c
	cc -o $@ $(LDFLAGS) -lpcap $<
