#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <pcap/pcap.h>

// these should be made into command line options

#define LISTEN_PORT 37008
#define RECV_BUFFER_SIZE 65535
#define DEST_FILENAME "-"

// constants

#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_RESERVED 2
#define TZSP_TYPE_CONFIGURATION 3
#define TZSP_TYPE_KEEPALIVE 4
#define TZSP_TYPE_PORT_OPENER 5

#define TZSP_TAG_END 1
#define TZSP_TAG_PADDING 0

struct tzsp_header {
    uint8_t version;
    uint8_t  type;
    uint16_t protocol;
} __attribute__((packed));

struct tzsp_tag {
    uint8_t type;
    uint8_t length;
    char  data[1];
} __attribute__((packed));

int terminate_requested = 0;

void request_terminate_handler(int signum) {
    terminate_requested = 1;
}

int setup_tzsp_listener() {
    int result;

    int sockfd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == -1) {
	perror("socket()");
	goto err_exit;
    }

    struct sockaddr_in6 listen_address = {
	.sin6_len = sizeof(struct sockaddr_in6),
	.sin6_family = AF_INET6,
	.sin6_port = ntohs(LISTEN_PORT),
	.sin6_flowinfo = 0,
	.sin6_addr = in6addr_any,
    };

    result = bind(sockfd, (struct sockaddr*) &listen_address, sizeof(listen_address));
    if (result == -1) {
	perror("bind()");
	goto err_close;
    }

    return sockfd;

err_close:
    close(sockfd);

err_exit:
    return -1;
}

void cleanup_tzsp_listener(int socket) {
    close(socket);
}

void trap_signal(int signum) {
    if (signal(signum, request_terminate_handler) == SIG_IGN)
	signal(signum, SIG_IGN);
}

int main(int argc, char **argv) {
    trap_signal(SIGINT);
    trap_signal(SIGHUP);
    trap_signal(SIGTERM);

    int tzsp_listener = setup_tzsp_listener();
    if (tzsp_listener == -1) {
	fprintf(stderr, "Could not setup tzsp listener\n");
	return -1;
    }

    pcap_t *pcap = pcap_open_dead(DLT_EN10MB, RECV_BUFFER_SIZE);
    if (!pcap) {
	fprintf(stderr, "Could not init pcap\n");
	goto err_cleanup_tzsp;
    }
    pcap_dumper_t *pcap_dumper = pcap_dump_open(pcap, DEST_FILENAME);
    if (!pcap_dumper) {
	fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(pcap));
	goto err_cleanup_pcap;
    }

    void *recv_buffer = malloc(RECV_BUFFER_SIZE);
    if (!recv_buffer) {
	fprintf(stderr, "Could not allocate receive buffer of %i bytes",
		RECV_BUFFER_SIZE);
	goto err_cleanup_pcap;
    }
    while (!terminate_requested) {
	if (terminate_requested) {
	    break;
	}
	ssize_t readsz =
	    recvfrom(tzsp_listener, recv_buffer, RECV_BUFFER_SIZE, 0,
		     NULL, NULL);

	void *p = recv_buffer;

	if (readsz == -1) {
	    perror("recv()");
	    break;
	}

	void *end = recv_buffer + readsz;

	if (p + sizeof(struct tzsp_header) > end)
	    break;

	struct tzsp_header *hdr = recv_buffer;

	p += sizeof(struct tzsp_header);

	if (hdr->version == 1 &&
	    hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST)
	{
	    while (p < end) {
		struct tzsp_tag *tag = p;
		if (tag->type == TZSP_TAG_END) {
		    p = ((char*) p) + 1;
		    break;
		}
		else if (tag->type == TZSP_TAG_PADDING) {
		    p = ((char*) p) + 1;
		}
		else {
		    p += tag->length;
		}
	    }
	}

	// packet remains starting at p
	struct pcap_pkthdr pcap_hdr = {
	    .caplen = readsz - (p - recv_buffer),
	    .len = readsz - (p - recv_buffer),
	};
	gettimeofday(&pcap_hdr.ts, NULL);
	pcap_dump((unsigned char*) pcap_dumper, &pcap_hdr, p);
    }

    free(recv_buffer);

err_cleanup_pcap:
    if (pcap_dumper)
	pcap_dump_close(pcap_dumper);

    if (pcap)
	pcap_close(pcap);

err_cleanup_tzsp:
    if (tzsp_listener != -1)
	cleanup_tzsp_listener(tzsp_listener);

exit:
    return 0;
}
