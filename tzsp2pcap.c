#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <pcap/pcap.h>

// these should be made into command line options

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
	uint8_t type;
	uint16_t protocol;
} __attribute__((packed));

struct tzsp_tag {
	uint8_t type;
	uint8_t length;
	char  data[1];
} __attribute__((packed));

static int self_pipe_fds[2];
static char flush_every_packet;

void request_terminate_handler(int signum) {
	if (signal(signum, SIG_DFL) == SIG_IGN)
		signal(signum, SIG_IGN);

	fprintf(stderr, "Caught signal, exiting (once more to force)\n");

	char data = 0;
	if (write(self_pipe_fds[1], &data, sizeof(data)) == -1) {
		perror("write");
	}
}

int setup_tzsp_listener(uint16_t listen_port) {
	int result;

	int sockfd = socket(PF_INET6, SOCK_DGRAM, IPPROTO_UDP);
	if (sockfd == -1) {
		perror("socket()");
		goto err_exit;
	}

	int on = 0;
	result = setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY,
	                    (void*)&on, sizeof(on));
	if (result == -1) {
		perror("setsockopt()");
		goto err_close;
	}

	struct sockaddr_in6 listen_address = {
		#ifdef SIN6_LEN
		.sin6_len = sizeof(struct sockaddr_in6),
		#endif

		.sin6_family = AF_INET6,
		.sin6_port = ntohs(listen_port),
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

static inline int max(int x, int y) {
	return (x > y) ? x : y;
}

void usage(const char *program) {
	fprintf(stderr,
	        "tzsp2pcap: listens on PORT and outputs to stdout\n"
	        "Usage %s [-h] [-f] [-p PORT]\n"
	        "\t-h\tDisplay this message\n"
	        "\t-f\tFlush stdout after every packet\n"
	        "\t-p PORT \tSpecify port to listen to\n",
	        program);
}

int main(int argc, char **argv) {
	int retval = 0;

	uint16_t listen_port = 37008;

	int ch;
	while ((ch = getopt(argc, argv, "fp:")) != -1) {
		switch (ch) {
		case 'f':
			flush_every_packet = 1;
			break;

		case 'p':
			listen_port = atoi(optarg);
			break;

		default:
			retval = -1;

		case 'h':
			usage(argv[0]);
			goto exit;
		}
	}

	trap_signal(SIGINT);
	trap_signal(SIGHUP);
	trap_signal(SIGTERM);

	if (pipe(self_pipe_fds) == -1) {
		perror("Creating self-wake pipe\n");
		retval = errno;
		goto exit;
	}

	int tzsp_listener = setup_tzsp_listener(listen_port);
	if (tzsp_listener == -1) {
		fprintf(stderr, "Could not setup tzsp listener\n");
		retval = errno;
		goto err_cleanup_pipe;
	}

	pcap_t *pcap = pcap_open_dead(DLT_EN10MB, RECV_BUFFER_SIZE);
	if (!pcap) {
		fprintf(stderr, "Could not init pcap\n");
		retval = -1;
		goto err_cleanup_tzsp;
	}
	pcap_dumper_t *pcap_dumper = pcap_dump_open(pcap, DEST_FILENAME);
	if (!pcap_dumper) {
		fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(pcap));
		retval = -1;
		goto err_cleanup_pcap;
	}

	char *recv_buffer = malloc(RECV_BUFFER_SIZE);
	if (!recv_buffer) {
		fprintf(stderr, "Could not allocate receive buffer of %i bytes",
		        RECV_BUFFER_SIZE);
		retval = -1;
		goto err_cleanup_pcap;
	}
	while (1) {
		fd_set read_set;
		FD_ZERO(&read_set);
		FD_SET(tzsp_listener, &read_set);
		FD_SET(self_pipe_fds[0], &read_set);
		if (select(max(tzsp_listener, self_pipe_fds[0]) + 1,
		           &read_set, NULL, NULL,
		           NULL) == -1)
		{
			if (errno == EINTR) continue;
			perror("select");
		}

		if (FD_ISSET(self_pipe_fds[0], &read_set)) {
			break;
		}

		assert(FD_ISSET(tzsp_listener, &read_set));

		ssize_t readsz =
		    recvfrom(tzsp_listener, recv_buffer, RECV_BUFFER_SIZE, 0,
		             NULL, NULL);

		char *p = recv_buffer;

		if (readsz == -1) {
			perror("recv()");
			break;
		}

		char *end = recv_buffer + readsz;

		if (p + sizeof(struct tzsp_header) > end)
			break;

		struct tzsp_header *hdr = (struct tzsp_header *) recv_buffer;

		p += sizeof(struct tzsp_header);

		if (hdr->version == 1 &&
		    hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST)
		{
			while (p < end) {
				struct tzsp_tag *tag = (struct tzsp_tag *) p;
				if (tag->type == TZSP_TAG_END) {
					p++;
					break;
				}
				else if (tag->type == TZSP_TAG_PADDING) {
					p++;
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
		pcap_dump((unsigned char*) pcap_dumper, &pcap_hdr, (unsigned char *) p);
		if (flush_every_packet)
			fflush(NULL);
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

err_cleanup_pipe:
	close(self_pipe_fds[0]);
	close(self_pipe_fds[1]);

exit:
	return retval;
}
