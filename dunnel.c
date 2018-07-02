#include <err.h>
#include <dtls.h>
#include <dtls_debug.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dat.h"
#include "fns.h"

/**
 * The session used for the DTLS socket.
 */
session_t dsess;

/**
 * The address of the client socket from which we last
 * received a datagram.
 *
 * XXX: We don't support multiple clients.
 */
session_t csess;

/**
 * Whether dunnel was started in server mode using -s.
 */
int smode;

/**
 * The global DTLS context.
 */
static dtls_context_t *ctx;

#define newpollfd(FD) \
	(struct pollfd){.fd = FD, .events = POLLIN | POLLERR};

static void
usage(char *progname)
{
	fprintf(stderr, "Usage: %s "
		"-s -v [LOG LEVEL] -a [ADDR] -p [PORT] "
		"-i [ID FILE] -k [KEY FILE] "
		"DTLS_HOST DTLS_PORT\n", progname);
	exit(EXIT_FAILURE);
}

static void
handle(int fd, struct dctx *dctx)
{
	ssize_t r;
	session_t sess, *sptr;
	unsigned char buf[DTLS_MAX_BUF];

	memset(&sess, '\0', sizeof(sess));
	if (dctx->ufd == fd) {
		sptr = (smode) ? &sess : &csess;
	} else { /* dtls socket */
		sptr = (smode) ? &csess : &sess;
	}

	sptr->size = sizeof(sptr->addr);
	if ((r = recvfrom(fd, buf, DTLS_MAX_BUF, MSG_DONTWAIT,
			&sptr->addr.sa, &sptr->size)) == -1) {
		warn("recvfrom failed");
		return;
	}

	if (dctx->ufd == fd) {
		sptr = (smode) ? &csess : &dsess;
		if (dtls_write(ctx, sptr, buf, r) == -1) {
			warnx("dtls_write failed");
			return;
		}
	} else {
		dtls_handle_message(ctx, sptr, buf, r);
	}
}

static void
ploop(struct dctx *dctx)
{
	size_t i;
	short ev;
	nfds_t nfds;
	int fd, ufd, dfd;
	struct pollfd fds[2];

	nfds = sizeof(fds) / sizeof(fds[0]);
	dfd = dctx->dfd;
	ufd = dctx->ufd;

	fds[0] = newpollfd(dfd);
	fds[1] = newpollfd(ufd);

	for (;;) {
		if (poll(fds, nfds, -1) == -1)
			err(EXIT_FAILURE, "poll failed");

		for (i = 0; i < nfds; i++) {
			fd = fds[i].fd;
			ev = fds[i].revents;

			if (ev & POLLIN) {
				handle(fd, dctx);
			} else if (ev & POLLERR) {
				errx(EXIT_FAILURE, "Received POLLERR on %s socket\n",
					(fd == ufd) ? "UDP" : "DTLS");
			}
		}
	}
}

int
main(int argc, char **argv)
{
	int opt, ufd;
	sockop uop, dop;
	struct dctx *dctx;
	unsigned char *key, *id;
	char *uaddr, *uport, *daddr, *dport;

	smode = 0;
	uaddr = uport = NULL;
	key = id = NULL;

	dtls_init();
	while ((opt = getopt(argc, argv, "a:i:k:p:sv:")) != -1) {
		switch (opt) {
		case 'a':
			uaddr = optarg;
			break;
		case 'i':
			if (!(id = readfile(optarg)))
				err(EXIT_FAILURE, "couldn't read identity");
			break;
		case 'k':
			if (!(key = readfile(optarg)))
				err(EXIT_FAILURE, "couldn't read key");
			break;
		case 'p':
			uport = optarg;
			break;
		case 's': /* act as dtls server, default: act as dtls client */
			smode = 1;
			break;
		case 'v':
			dtls_set_log_level(atoi(optarg));
			break;
		default:
			usage(*argv);
			break;
		}
	}

	if (smode) {
		uop = SOCK_CONN;
		dop = SOCK_BIND;
	} else {
		uop = SOCK_BIND;
		dop = SOCK_CONN;
	}

	if (argc <= 2 || optind + 1 >= argc)
		usage(*argv);
	else if (!key || !id)
		errx(EXIT_FAILURE, "A key and an identity must be provided");

	daddr = argv[optind];
	dport = argv[optind + 1];

	if ((ufd = usock(uaddr, (!uport) ? dport : uport, uop)) == -1)
		err(EXIT_FAILURE, "usock failed");
	if (!(ctx = dsock(daddr, dport, ufd, dop)))
		err(EXIT_FAILURE, "dsock failed");

	/**
	 * TODO: don't extract the `struct dctx` from the tinydtls context.
	 */
	dctx = dtls_get_app_data(ctx);
	dctx->key = key;
	dctx->id = id;

	ploop(dctx);
	return EXIT_SUCCESS;
}
