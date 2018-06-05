#include <err.h>
#include <dtls.h>
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
 * The global DTLS context.
 */
static dtls_context_t *ctx;

#define newpollfd(FD) \
	(struct pollfd){.fd = FD, .events = POLLIN | POLLERR};

static void
usage(char *progname)
{
	fprintf(stderr, "Usage: %s "
		"-a [ADDR] -p [PORT] "
		"DTLS_HOST DTLS_PORT\n", progname);
	exit(EXIT_FAILURE);
}

static void
hdtls(int fd)
{
	ssize_t r;
	session_t sess;
	unsigned char buf[DTLS_MAX_BUF];

	memset(&sess, '\0', sizeof(sess));
	sess.size = sizeof(sess.addr);

	if ((r = recvfrom(fd, buf, DTLS_MAX_BUF, MSG_DONTWAIT,
			&sess.addr.sa, &sess.size)) == -1) {
		warn("dtls recvfrom failed");
		return;
	}

	/* TODO: what are we supposed to do with the return value? */
	dtls_handle_message(ctx, &sess, buf, r);
}

static void
hudp(int fd)
{
	ssize_t r;
	unsigned char buf[DTLS_MAX_BUF];

	if ((r = recv(fd, buf, DTLS_MAX_BUF, MSG_DONTWAIT)) == -1) {
		warn("udp recv failed");
		return;
	}

	if (dtls_write(ctx, &dsess, buf, r) == -1) {
		warn("dtls_write failed");
		return;
	}
}

void
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

	fds[0] = newpollfd(ufd);
	fds[1] = newpollfd(dfd);

	for (;;) {
		if (poll(fds, nfds, -1) == -1)
			err(EXIT_FAILURE, "poll failed");

		for (i = 0; i < nfds; i++) {
			fd = fds[i].fd;
			ev = fds[i].revents;

			if (ev & POLLERR) {
				warnx("Received POLLERR on FD %d\n", fd);
				continue;
			} else if (!(ev & POLLIN)) {
				continue;
			}

			if (fd == dfd) {
				hdtls(dfd);
			} else { /* fd == ufd */
				hudp(ufd);
			}
		}
	}
}

int
main(int argc, char **argv)
{
	int opt, ufd;
	char *uaddr, *uport, *daddr, *dport;

	uaddr = uport = NULL;
	while ((opt = getopt(argc, argv, "a:p:")) != -1) {
		switch (opt) {
		case 'a':
			uaddr = optarg;
			break;
		case 'p':
			uport = optarg;
			break;
		default:
			usage(*argv);
			break;
		}
	}

	if (argc <= 2 || optind + 1 >= argc)
		usage(*argv);
	dtls_init();

	daddr = argv[optind];
	dport = argv[optind + 1];

	if ((ufd = usock(uaddr, (!uport) ? dport : uport)) == -1)
		err(EXIT_FAILURE, "usock failed");
	if (!(ctx = dsock(daddr, dport, ufd)))
		err(EXIT_FAILURE, "dsock failed");

	ploop(dtls_get_app_data(ctx));
	return EXIT_SUCCESS;
}
