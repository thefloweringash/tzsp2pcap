#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <linux/limits.h> // max MAX_PATH

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

/**
 * We pass this struct around
 */
struct my_pcap_t {

    pcap_t *pcap;

    const char *orig_filename;    // original filename
    const char *filename;         // current filename
    FILE *fp;               // file pointer 

    pcap_dumper_t *dumper;  // pcap dumper

    int gflag;
    time_t gflag_time;
    int cflag;
    int cflag_count;

};

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

static const char *get_filename(struct my_pcap_t *my_pcap){
    if (strcmp(my_pcap->orig_filename, "-") == 0) {
        return strdup(my_pcap->orig_filename);
    }

    const char *filename = malloc(PATH_MAX + 1);

    if (filename == NULL)
        perror("get_filename: malloc");

    /**
     * We use strftime only for gflag
     */
    if (my_pcap->gflag > 0) {

        struct tm *local_tm;

        /* Convert gflag_time to a usable format */
        if ((local_tm = localtime(&my_pcap->gflag_time)) == NULL) {
            perror("localtime");
            // fallback to original file
            snprintf((char *)filename, PATH_MAX +1, "%s", my_pcap->orig_filename);
        }
        else {
            /* There's no good way to detect an error in strftime since a return
             * value of 0 isn't necessarily failure.
             */
            strftime((char *)filename, PATH_MAX, my_pcap->orig_filename, local_tm);
        }
    }
    else {
        if (my_pcap->cflag > 0 && my_pcap->cflag_count > 0){
            if (snprintf((char *)filename, PATH_MAX + 1, "%s.%d", my_pcap->orig_filename, my_pcap->cflag_count) > PATH_MAX){
                // back to old file
                fprintf(stderr, "Warning: Filename is too long: > %d\n", PATH_MAX);
                snprintf((char *)filename, PATH_MAX +1, "%s", my_pcap->orig_filename);
            }
        }
        else {
            snprintf((char *)filename, PATH_MAX + 1, "%s", my_pcap->orig_filename);
        }
    }
    return filename;

}

static int make_dumper(struct my_pcap_t *my_pcap, int verbose){

    const char *new_filename = get_filename(my_pcap);

    if (new_filename == NULL) {
        fprintf(stderr, "Could not get filename\n");
        return -1;
    }

    if (verbose >= 1){
        fprintf(stderr, "Creating new dump file: %s\n", new_filename);
    }

    if (my_pcap->dumper == NULL) {
        my_pcap->dumper = pcap_dump_open(my_pcap->pcap, new_filename);
        if (!my_pcap->dumper) {
            fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(my_pcap->pcap));
            return -1;
        }
    }
    else {
        pcap_dump_close(my_pcap->dumper);
        my_pcap->fp = NULL;
        my_pcap->dumper = pcap_dump_open(my_pcap->pcap, new_filename);
        if (!my_pcap->dumper) {
            fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(my_pcap->pcap));
            return -1;
        }
    }
    if (my_pcap->fp == NULL) {
        my_pcap->fp = pcap_dump_file(my_pcap->dumper);
    }

    if (my_pcap->filename != NULL){
        free((void *)my_pcap->filename);
    }
    my_pcap->filename = new_filename;

    return 0;
}

static int check_dumper(struct my_pcap_t *my_pcap, int verbose){

    if (my_pcap->cflag > 0) {
#ifdef HAVE_PCAP_FTELL64
        int64_t size = pcap_dump_ftell64(my_pcap->dumper);
#else
        /*
         * XXX - this only handles a Cflag value > 2^31-1 on
         * LP64 platforms; to handle ILP32 (32-bit UN*X and
         * Windows) or LLP64 (64-bit Windows) would require
         * a version of libpcap with pcap_dump_ftell64().
         */
        long size = pcap_dump_ftell(my_pcap->dumper);
#endif
        fprintf(stderr, "Current size: %lu\n", size);
        if (size > my_pcap->cflag) {
            ++my_pcap->cflag_count;
            return make_dumper(my_pcap, verbose);
        }
    }

    else if(my_pcap->gflag > 0){
        /* Check if it is time to rotate */
        time_t t;

        /* Get the current time */
        if ((t = time(NULL)) == (time_t)-1) {
            perror("Can't get current_time");
            return errno;
        }
        if (t - my_pcap->gflag_time >= my_pcap->gflag){
            my_pcap->gflag_time = t;
            return make_dumper(my_pcap, verbose);
        }
    }

    return 0;
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
	        "Usage %s [-h] [-v] [-f] [-p PORT] [-o FILENAME] [-s SIZE] [-G SECONDS] [-C SIZE]\n"
	        "\t-h           Display this message\n"
	        "\t-v           Verbose (repeat to increase up to -vv)\n"
	        "\t-f           Flush output after every packet\n"
	        "\t-p PORT      Specify port to listen on  (defaults to %u)\n"
	        "\t-o FILENAME  Write output to FILENAME   (defaults to stdout)\n"
	        "\t-s SIZE      Receive buffer size        (defaults to %u)\n"
            "\t-G SECONDS   Rotate file every n seconds\n"
            "\t-C FILESIZE  Rotate file when FILESIZE is reached\n",
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
    int gflag = 0;
    time_t gflag_time = 0; // for time
    int cflag = 0;
    int cflag_count = 0; // number of files

	int ch;
	while ((ch = getopt(argc, argv, "fp:o:s:C:G:vh")) != -1) {
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

        case 'G':
            gflag = atoi(optarg);
            if (gflag <= 0) {
                fprintf(stderr, "Invalid -G seconds provided\n");
                retval = -1;
                goto exit;
            }
            /* Grab the current time for rotation use. */
            if ((gflag_time = time(NULL)) == (time_t)-1) {
                perror("Cannot get current time");
                retval = errno;
                goto exit;
            }
            break;

        case 'C':
            cflag = atoi(optarg);
            if (cflag <= 0) {
                fprintf(stderr, "Invalid -C filesize provided\n");
                retval = -1;
                goto exit;
            }
            break;

		default:
			retval = -1;

		case 'h':
			usage(argv[0]);
			goto exit;
		}
	}

    /**
     * Cannot have both -C and -G provided
     */
    if (cflag > 0 && gflag > 0) {
        fprintf(stderr, "Cannot use both -C and -G\n");
        retval = -1;
        goto exit;
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

    struct my_pcap_t my_pcap;
    FILE *pcap_dumper_file = NULL;
    pcap_dumper_t *pcap_dumper = NULL;

    // copy everything to our structure
    my_pcap.pcap = pcap;
    my_pcap.orig_filename = out_filename;
    my_pcap.filename = NULL;
    my_pcap.fp = pcap_dumper_file;
    my_pcap.dumper = pcap_dumper;
    my_pcap.gflag = gflag;
    my_pcap.gflag_time = gflag_time;
    my_pcap.cflag = cflag;
    my_pcap.cflag_count = cflag_count;

    if (make_dumper(&my_pcap, verbose) == -1){
        retval = -1;
        goto err_cleanup_pcap;
    }

    pcap_dumper_file = my_pcap.fp;
    pcap_dumper = my_pcap.dumper;

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

        // copy again from our structure
        pcap_dumper_file = my_pcap.fp;
        pcap_dumper = my_pcap.dumper;        

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
			if (pcap_dump_flush(pcap_dumper) != 0) {
				fprintf(stderr, "error flushing via pcap_dump_flush\n");
				break;
			}
		}

        /**
         * Check if -G or -C was provided and if out_filename is not stderr
         */
        if ((gflag > 0 || cflag > 0) && strcmp(out_filename, "-") != 0) {
            if (check_dumper(&my_pcap, verbose) != 0){
                retval = -1;
                goto err_cleanup_pcap;
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
