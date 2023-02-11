#include <sys/types.h>
#include <sys/wait.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <getopt.h>

#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>

#include <sys/time.h>
#include <sys/resource.h>

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
 * Application instance type
 */
struct my_pcap_t {
	pcap_t *pcap;

	const char *filename_template;
	const char *filename;

	pcap_dumper_t *dumper;
	FILE *fp;               // dumper's underlying file

	int verbose;

	int rotation_interval;
	time_t rotation_start_time;
	int rotation_size_threshold;
	int rotation_count;
	const char *postrotate_command;
};

static int self_pipe_fds[2];
static int extcap_mode = 0;

static void request_terminate_handler(int signum) {
	signal(signum, SIG_DFL);

	if (!extcap_mode)
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

static void catch_child(int sig_num) {
	(void) sig_num;

	/* when we get here, we know there's a zombie child waiting */
	int child_status;

	wait(&child_status);
}

static const char *get_filename(struct my_pcap_t *my_pcap) {
	if (my_pcap->rotation_interval > 0) {
		/**
		 * When using a rotation_interval, filename templates are
		 * format strings for strftime.
		 */
		struct tm *local_tm;

		/* Convert rotation_start_time to a format accepted by strftime */
		if ((local_tm = localtime(&my_pcap->rotation_start_time)) == NULL) {
			perror("localtime");
			return NULL;
		}

		char *filename = malloc(PATH_MAX);

		if (filename == NULL) {
			perror("get_filename: malloc");
			return NULL;
		}

		if (strftime((char *)filename, PATH_MAX, my_pcap->filename_template, local_tm) == 0) {
			fprintf(stderr, "get_filename: size of template expanded via strftime exceeded PATH_MAX\n");
			return NULL;
		}

		return filename;
	}

	if (my_pcap->rotation_size_threshold > 0 && my_pcap->rotation_count > 0) {
		char *filename = malloc(PATH_MAX);

		if (snprintf(filename, PATH_MAX, "%s.%d", my_pcap->filename_template, my_pcap->rotation_count) >= PATH_MAX) {
			fprintf(stderr, "get_filename: size of template with count suffix exceeded PATH_MAX\n");
			return NULL;
		}

		return filename;
	}

	return strdup(my_pcap->filename_template);
}

static void run_postrotate_command(struct my_pcap_t *my_pcap, const char *filename) {
	if (my_pcap->verbose >= 1) {
		fprintf(stderr, "Running post-rotate command: %s\n", my_pcap->postrotate_command);
	}

	pid_t child;

	child = fork();
	if (child == -1) {
		perror("run_postrotate_command: fork failed");
		return;
	}
	if (child != 0) {
		/* Parent process. */
		return;
	}

	/*
	 * Child process.
	 * Set to lowest priority so that this doesn't disturb the capture.
	 */
#ifdef NZERO
	setpriority(PRIO_PROCESS, 0, NZERO - 1);
#else
	setpriority(PRIO_PROCESS, 0, 19);
#endif
	if (execlp(my_pcap->postrotate_command, my_pcap->postrotate_command, filename, NULL) == -1) {
		fprintf(stderr,
		        "after_logrotate: execlp(%s, %s) failed: %s\n",
		        my_pcap->postrotate_command,
		        filename,
		        strerror(errno));
    }
	exit(1);
}

static int open_dumper(struct my_pcap_t *my_pcap, const char *filename) {
	if (my_pcap->verbose >= 1) {
		fprintf(stderr, "Opening output file: %s\n", filename);
	}

	pcap_dumper_t *dumper;
	dumper = pcap_dump_open(my_pcap->pcap, filename);
	if (!dumper) {
		fprintf(stderr, "Could not open output file: %s\n", pcap_geterr(my_pcap->pcap));
		return -1;
	}

	my_pcap->dumper   = dumper;
	my_pcap->filename = filename;
	my_pcap->fp       = pcap_dump_file(my_pcap->dumper);

	return 0;
}

static void close_dumper(struct my_pcap_t *my_pcap) {
	pcap_dump_close(my_pcap->dumper);
	my_pcap->dumper   = NULL;
	my_pcap->filename = NULL;
	my_pcap->fp       = NULL;
}

static int rotate_dumper(struct my_pcap_t *my_pcap) {
	const char *new_filename = get_filename(my_pcap);

	if (new_filename == NULL) {
		fprintf(stderr, "Could not get filename\n");
		return -1;
	}

	const char *rotated_filename = my_pcap->filename;

	if (my_pcap->verbose) {
		fprintf(stderr, "Rotating output file: %s -> %s\n",
		        rotated_filename, new_filename);
	}

	close_dumper(my_pcap);

	if (open_dumper(my_pcap, new_filename) != 0) {
		fprintf(stderr, "Error re-opening dumper\n");
		return -1;
	}

	if (my_pcap->postrotate_command != NULL) {
		run_postrotate_command(my_pcap, rotated_filename);
	}

	free((void*) rotated_filename);

	return 0;
}

static int maybe_rotate(struct my_pcap_t *my_pcap) {

	if (my_pcap->rotation_size_threshold > 0) {
#ifdef HAVE_PCAP_FTELL64
		int64_t size = pcap_dump_ftell64(my_pcap->dumper);
#else
		/*
		 * XXX - this only handles a rotation_size_threshold value >
		 * 2^31-1 on LP64 platforms; to handle ILP32 (32-bit UN*X and
		 * Windows) or LLP64 (64-bit Windows) would require a version
		 * of libpcap with pcap_dump_ftell64().
		 */
		long size = pcap_dump_ftell(my_pcap->dumper);
#endif
		if (size > my_pcap->rotation_size_threshold) {
			++my_pcap->rotation_count;
			return rotate_dumper(my_pcap);
		}
	}

	else if (my_pcap->rotation_interval > 0) {
		/* Check if it is time to rotate */
		time_t now;

		/* Get the current time */
		if ((now = time(NULL)) == (time_t) -1) {
			perror("Can't get current_time");
			return errno;
		}
		if (now - my_pcap->rotation_start_time >= my_pcap->rotation_interval) {
			my_pcap->rotation_start_time = now;
			return rotate_dumper(my_pcap);
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
	        "Usage %s [-h] [-v] [-f] [-p PORT] [-o FILENAME] [-s SIZE] [-G SECONDS] [-C SIZE] [-z CMD]\n"
	        "\t-h           Display this message\n"
	        "\t-v           Verbose (repeat to increase up to -vv)\n"
	        "\t-f           Flush output after every packet\n"
	        "\t-p PORT      Specify port to listen on  (defaults to %u)\n"
	        "\t-o FILENAME  Write output to FILENAME   (defaults to stdout)\n"
	        "\t-s SIZE      Receive buffer size        (defaults to %u)\n"
	        "\t-G SECONDS   Rotate file every n seconds\n"
	        "\t-C FILESIZE  Rotate file when FILESIZE is reached\n"
	        "\t-z CMD       Post-rotate command to execute\n",
	        program,
	        DEFAULT_LISTEN_PORT,
	        DEFAULT_RECV_BUFFER_SIZE);
}

int main(int argc, char **argv) {
	int retval = 0;

	int         recv_buffer_size  = DEFAULT_RECV_BUFFER_SIZE;
	uint16_t    listen_port       = DEFAULT_LISTEN_PORT;

	struct my_pcap_t my_pcap = {
	    .pcap                    = NULL,
	    .filename_template       = strdup(DEFAULT_OUT_FILENAME),
	    .filename                = NULL,
	    .fp                      = NULL,
	    .dumper                  = NULL,
	    .verbose                 = 0,
	    .rotation_interval       = 0,
	    .rotation_start_time     = 0,
	    .rotation_size_threshold = 0,
	    .rotation_count          = 0,
	    .postrotate_command      = NULL,
	};

    char flush_every_packet = 0;

    static struct option long_options[] = {
                {"extcap-interfaces",     no_argument,       0, 0},
                {"extcap-interface",      required_argument, 0, 0},
                {"extcap-version",        required_argument, 0, 0},
                {"extcap-config",         no_argument,       0, 0},
                {"extcap-dlts",           no_argument,       0, 0},
                {"extcap-capture-filter", required_argument, 0, 0},
                {"capture",               no_argument,       0, 0},
                {"fifo",                  required_argument, 0, 0},
                {0, 0,0, 0}
        };

	int ch;
	int option_index = 0;
	while ((ch = getopt_long(argc, argv, "fp:o:s:C:G:z:vh", long_options, &option_index)) != -1) {
		switch (ch) {
		case '\0':
			if (long_options[option_index].flag != 0)
				break;

			const char *option_name = long_options[option_index].name;

			if (!strcmp(option_name, "extcap-interfaces")) {
			    printf("extcap {version=0.1.0}{help=file:///no/help}\n"
                       "interface {value=tzsp2pcap}{display=Mikrotik capture protocol}\n");
			    exit(0);
			}

            if (!strcmp(option_name, "extcap-config")) {
                exit(0);
            }

            if (!strcmp(option_name, "extcap-dlts")) {
                printf("dlt {number=147}{name=tzsp2pcap}{display=TZSP to pcap DLT}\n");
                exit(0);
            }

            if (!strcmp(option_name, "fifo")) {
                if (my_pcap.filename_template) {
                    free((void*) my_pcap.filename_template);
                }
                my_pcap.filename_template = strdup(optarg);
                break;
            }

            if (!strcmp(option_name, "capture")) {
                extcap_mode = 1;
                flush_every_packet = 1;
                break;
            }

            break;
		case 'f':
			flush_every_packet = 1;
			break;

		case 'p':
			listen_port = atoi(optarg);
			break;

		case 'o':
			if (my_pcap.filename_template) {
				free((void*) my_pcap.filename_template);
			}
			my_pcap.filename_template = strdup(optarg);
			break;

		case 's':
			recv_buffer_size = atoi(optarg);
			break;

		case 'v':
			my_pcap.verbose++;
			break;

		case 'G': {
			int rotation_interval = atoi(optarg);
			if (rotation_interval <= 0) {
				fprintf(stderr, "Invalid -G seconds provided\n");
				retval = -1;
				goto exit;
			}

			time_t now;
			if ((now = time(NULL)) == (time_t) -1) {
				perror("Cannot get current time");
				retval = errno;
				goto exit;
			}

			my_pcap.rotation_interval   = rotation_interval;
			my_pcap.rotation_start_time = now;

			break;
		}

		case 'C': {
			int rotation_size_threshold = atoi(optarg);
			if (rotation_size_threshold <= 0) {
				fprintf(stderr, "Invalid -C filesize provided\n");
				retval = -1;
				goto exit;
			}
			my_pcap.rotation_size_threshold = rotation_size_threshold;
			break;
		}

		case 'z':
			my_pcap.postrotate_command = strdup(optarg);
			break;

		default:
			retval = -1;
			/* FALLTHRU */

		case 'h':
			usage(argv[0]);
			goto exit;
		}
	}

	/**
	 * Cannot have both -C and -G provided
	 */
	if (my_pcap.rotation_size_threshold > 0 && my_pcap.rotation_interval > 0) {
		fprintf(stderr, "Cannot use both -C and -G\n");
		retval = -1;
		goto exit;
	}

	trap_signal(SIGINT);
	trap_signal(SIGHUP);
	trap_signal(SIGTERM);
	signal(SIGCHLD, catch_child);

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

	{
		pcap_t *pcap = pcap_open_dead(DLT_EN10MB, recv_buffer_size);
		if (!pcap) {
			fprintf(stderr, "Could not init pcap\n");
			retval = -1;
			goto err_cleanup_tzsp;
		}
		my_pcap.pcap = pcap;
	}

	{
		const char *initial_filename = get_filename(&my_pcap);
		if (!initial_filename) {
			fprintf(stderr, "Could not get initial filename\n");
			retval = -1;
			goto err_cleanup_pcap;
		}

		if (open_dumper(&my_pcap, initial_filename) == -1) {
			retval = -1;
			goto err_cleanup_pcap;
		}

		if ((my_pcap.rotation_size_threshold > 0 || my_pcap.rotation_interval > 0)) {
			struct stat fp_stat;

			if (fstat(fileno(my_pcap.fp), &fp_stat) == -1) {
				perror("fstat");
				retval = errno;
				goto err_cleanup_pcap;
			}

			if (!(fp_stat.st_mode & S_IFREG)) {
				fprintf(stderr, "Output is not a regular file, but rotation was requested.\n");
				retval = -1;
				goto err_cleanup_pcap;
			}
		}
	}

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
		if (my_pcap.verbose >= 2) {
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

		if (my_pcap.verbose >= 2) {
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

		if (my_pcap.verbose) {
			fprintf(stderr,
			        "header { version = %u, type = %s(%u), encap = 0x%.4x }\n",
			        hdr->version,
			        name_tag(hdr->type,
			                 tzsp_type_names, ARRAYSZ(tzsp_type_names)),
			        hdr->type,
			        ntohs(hdr->encap));
		}

		char got_end_tag = 0;

		// We should only have to deal with packets of type "Received"
		// here, since we are sinking packets. However, some sniffers
		// send packets as "Transmit". While we're going to ignore the
		// intent of retransmitting the packet, there's still a valid
		// encapsulated packet here, which for the purpose of being
		// useful, we should still emit.
		if (hdr->version == 1 &&
		    (hdr->type == TZSP_TYPE_RECEIVED_TAG_LIST ||
		     hdr->type == TZSP_TYPE_PACKET_FOR_TRANSMIT))
		{
			while (p < end) {
				// some packets only have the type field, which is
				// guaranteed by (p < end).

				struct tzsp_tag *tag = (struct tzsp_tag *) p;

				if (my_pcap.verbose) {
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

		if (my_pcap.verbose) {
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
		pcap_dump((unsigned char*) my_pcap.dumper, &pcap_hdr, (unsigned char *) p);

		// since pcap_dump doesn't report errors directly, we have
		// to approximate by checking its underlying file.
		if (ferror(my_pcap.fp)) {
			fprintf(stderr, "error writing via pcap_dump\n");
			break;
		}

		if (flush_every_packet) {
			if (pcap_dump_flush(my_pcap.dumper) != 0) {
				fprintf(stderr, "error flushing via pcap_dump_flush\n");
				break;
			}
		}

		if (my_pcap.rotation_interval > 0 || my_pcap.rotation_size_threshold > 0) {
			if (maybe_rotate(&my_pcap) != 0) {
				retval = -1;
				goto err_cleanup_pcap;
			}
		}
	}

	free(recv_buffer);

err_cleanup_pcap:
	if (my_pcap.dumper)
		pcap_dump_close(my_pcap.dumper);

	if (my_pcap.pcap)
		pcap_close(my_pcap.pcap);

err_cleanup_tzsp:
	if (tzsp_listener != -1)
		cleanup_tzsp_listener(tzsp_listener);

err_cleanup_pipe:
	close(self_pipe_fds[0]);
	close(self_pipe_fds[1]);

exit:
	if (my_pcap.filename_template)
		free((void*) my_pcap.filename_template);

	if (my_pcap.filename)
		free((void*) my_pcap.filename);

	if (my_pcap.postrotate_command)
		free((void*) my_pcap.postrotate_command);

	return retval;
}
