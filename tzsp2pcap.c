#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <pcap/pcap.h>

#define ARRAYSZ(x) (sizeof(x)/sizeof(*x))

#define DEFAULT_RECV_BUFFER_SIZE 65535
#define DEFAULT_LISTEN_PORT 37008
#define DEFAULT_OUT_FILENAME "-"

// constants

#define TZSP_TYPE_RECEIVED_TAG_LIST 0
#define TZSP_TYPE_PACKET_FOR_TRANSMIT 1
#define TZSP_TYPE_RESERVED 2
#define TZSP_TYPE_CONFIGURATION 3
#define TZSP_TYPE_KEEPALIVE 4
#define TZSP_TYPE_PORT_OPENER 5

static const char * const tzsp_type_names[] = {
	[TZSP_TYPE_RECEIVED_TAG_LIST]   = "RECEIVED_TAG_LIST",
	[TZSP_TYPE_PACKET_FOR_TRANSMIT] = "PACKET_FOR_TRANSMIT",
	[TZSP_TYPE_RESERVED]            = "RESERVED",
	[TZSP_TYPE_CONFIGURATION]       = "CONFIGURATION",
	[TZSP_TYPE_KEEPALIVE]           = "KEEPALIVE",
	[TZSP_TYPE_PORT_OPENER]         = "PORT_OPENER",
};

#define TZSP_TAG_END 1
#define TZSP_TAG_PADDING 0

static const char * const tzsp_tag_names[] = {
	[TZSP_TAG_END]     = "END",
	[TZSP_TAG_PADDING] = "PADDING",
};

struct tzsp_header {
	uint8_t version;
	uint8_t type;
	uint16_t encap;
} __attribute__((packed));

struct tzsp_tag {
	uint8_t type;
	uint8_t length;
	char  data[];
} __attribute__((packed));

static int self_pipe_fds[2];

static void request_terminate_handler(int signum) {
	signal(signum, SIG_DFL);

	fprintf(stderr, "Caught signal, exiting (once more to force)\n");

	char data = 0;
	if (write(self_pipe_fds[1], &data, sizeof(data)) == -1) {
		perror("write");
	}
}

static int setup_tzsp_listener(uint16_t listen_port) {
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

static void cleanup_tzsp_listener(int socket) {
	close(socket);
}

static void trap_signal(int signum) {
	if (signal(signum, request_terminate_handler) == SIG_IGN)
		signal(signum, SIG_IGN);
}

static inline const char* name_tag(int tag,
                                   const char * const names[],
                                   int names_len) {
	if (tag >= 0 && tag < names_len) {
		return names[tag];
	}
	else {
		return "<UNKNOWN>";
	}
}

static inline int max(int x, int y) {
	return (x > y) ? x : y;
}

static void usage(const char *program) {
	fprintf(stderr,
	        "\n"
	        "tzsp2pcap: receive tazmen sniffer protocol over udp and\n"
	        "produce pcap formatted output\n"
	        "\n"
	        "Usage %s [-h] [-v] [-f] [-p PORT] [-o FILENAME] [-s SIZE]\n"
	        "\t-h           Display this message\n"
	        "\t-v           Verbose (repeat to increase up to -vv)\n"
	        "\t-f           Flush output after every packet\n"
	        "\t-p PORT      Specify port to listen on  (defaults to %u)\n"
	        "\t-o FILENAME  Write output to FILENAME   (defaults to stdout)\n"
	        "\t-s SIZE      Receive buffer size        (defaults to %u)\n",
	        program,
	        DEFAULT_LISTEN_PORT,
	        DEFAULT_RECV_BUFFER_SIZE);
}

int main(int argc, char **argv) {
	int retval = 0;

	int recv_buffer_size = DEFAULT_RECV_BUFFER_SIZE;
	uint16_t listen_port = DEFAULT_LISTEN_PORT;
	const char *out_filename = DEFAULT_OUT_FILENAME;
	char out_filename_cleanup = 0;
	char flush_every_packet = 0;
	int verbose = 0;

	int ch;
	while ((ch = getopt(argc, argv, "fp:o:s:vh")) != -1) {
		switch (ch) {
		case 'f':
			flush_every_packet = 1;
			break;

		case 'p':
			listen_port = atoi(optarg);
			break;

		case 'o':
			out_filename = strdup(optarg);
			out_filename_cleanup = 1;
			break;

		case 's':
			recv_buffer_size = atoi(optarg);
			break;

		case 'v':
			verbose++;
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

	pcap_t *pcap = pcap_open_dead(DLT_EN10MB, recv_buffer_size);
	if (!pcap) {
		fprintf(stderr, "Could not init pcap\n");
		retval = -1;
		goto err_cleanup_tzsp;
	}
	pcap_dumper_t *pcap_dumper = pcap_dump_open(pcap, out_filename);
	if (!pcap_dumper) {
		fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(pcap));
		retval = -1;
		goto err_cleanup_pcap;
	}

	FILE *pcap_dumper_file = pcap_dump_file(pcap_dumper);

	char *recv_buffer = malloc(recv_buffer_size);
	if (!recv_buffer) {
		fprintf(stderr, "Could not allocate receive buffer of %i bytes\n",
		        recv_buffer_size);
		retval = -1;
		goto err_cleanup_pcap;
	}

	while (1) {
		fd_set read_set;

next_packet:
		if (verbose >= 2) {
			fprintf(stderr, "loop_start\n");
		}

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
		    recvfrom(tzsp_listener, recv_buffer, recv_buffer_size, 0,
		             NULL, NULL);

		if (verbose >= 2) {
			fprintf(stderr,
			        "read 0x%.4zx bytes into buffer of size 0x%.4x\n",
			        readsz, recv_buffer_size);
		}

		char *p = recv_buffer;

		if (readsz == -1) {
			perror("recv()");
			break;
		}

		char *end = recv_buffer + readsz;

		if (p + sizeof(struct tzsp_header) > end) {
			fprintf(stderr, "Malformed packet (truncated header)\n");
			goto next_packet;
		}

		struct tzsp_header *hdr = (struct tzsp_header *) recv_buffer;

		p += sizeof(struct tzsp_header);

		if (verbose) {
			fprintf(stderr,
			        "header { version = %u, type = %s(%u), encap = 0x%.4x }\n",
			        hdr->version,
			        name_tag(hdr->type,
			                 tzsp_type_names, ARRAYSZ(tzsp_type_names)),
			        hdr->type,
			        ntohs(hdr->encap));
		}

		char got_end_tag = 0;

		if (hdr->version == 1 &&
		    hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST)
		{
			while (p < end) {
				// some packets only have the type field, which is
				// guaranteed by (p < end).

				struct tzsp_tag *tag = (struct tzsp_tag *) p;

				if (verbose) {
					fprintf(stderr,
					        "\ttag { type = %s(%u) }\n",
					        name_tag(tag->type,
					                 tzsp_tag_names, ARRAYSZ(tzsp_tag_names)),
					        tag->type);
				}

				if (tag->type == TZSP_TAG_END) {
					got_end_tag = 1;
					p++;
					break;
				}
				else if (tag->type == TZSP_TAG_PADDING) {
					p++;
				}
				else {
					if (p + sizeof(struct tzsp_tag) > end ||
					    p + sizeof(struct tzsp_tag) + tag->length > end)
					{
						fprintf(stderr, "Malformed packet (truncated tag)\n");
						goto next_packet;
					}
					p += sizeof(struct tzsp_tag) + tag->length;
				}
			}
		}
		else {
			fprintf(stderr, "Packet format not understood\n");
			goto next_packet;
		}

		if (!got_end_tag) {
			fprintf(stderr, "Packet truncated (no END tag)\n");
			goto next_packet;
		}

		if (verbose) {
			fprintf(stderr,
			        "\tpacket data begins at offset 0x%.4lx, length 0x%.4lx\n",
			        (p - recv_buffer),
			        readsz - (p - recv_buffer));
		}

		// packet remains starting at p
		struct pcap_pkthdr pcap_hdr = {
			.caplen = readsz - (p - recv_buffer),
			.len = readsz - (p - recv_buffer),
		};
		gettimeofday(&pcap_hdr.ts, NULL);
		pcap_dump((unsigned char*) pcap_dumper, &pcap_hdr, (unsigned char *) p);

		// since pcap_dump doesn't report errors directly, we have
		// to approximate by checking its underlying file.
		if (ferror(pcap_dumper_file)) {
			fprintf(stderr, "error writing via pcap_dump\n");
			break;
		}
		if (flush_every_packet) {
			if (fflush(pcap_dumper_file) != 0) {
				perror("fflush");
				break;
			}
		}
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
	if (out_filename_cleanup)
		free((void*) out_filename);

	return retval;
}
