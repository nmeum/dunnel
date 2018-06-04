#include <err.h>
#include <dtls.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

static dtls_context_t *ctx;
extern dtls_handler_t dtlscb;

#define BSIZ (BUFSIZ > DTLS_MAX_BUF) ? DTLS_MAX_BUF : BUFSIZ
#define newpollfd(FD) \
	(struct pollfd){.fd = FD, .events = POLLIN | POLLERR};

struct dctx {
	int ufd; /* FD of the UDP socket. */
	int dfd; /* FD of the DTLS socket. */
};

static void
usage(char *progname)
{
	fprintf(stderr, "Usage: %s "
		"-a [ADDR] -p [PORT] "
		"DTLS_HOST DTLS_PORT\n", progname);
	exit(EXIT_FAILURE);
}

static socklen_t
str2addr(char *host, char *port, struct sockaddr *dest)
{
	socklen_t len;
	struct addrinfo hint, *res, *r;

	memset(&hint, '\0', sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;

	if (getaddrinfo(host, port, &hint, &res)) {
		return 0;
	}

	len = 0;
	for (r = res; r != NULL; r = r->ai_next) {
		switch (r->ai_family) {
		case AF_INET6:
		case AF_INET:
			len = r->ai_addrlen;
			memcpy(dest, r->ai_addr, len);
			goto ret;
		default:
			errno = EAFNOSUPPORT;
			goto ret;
		}
	}

	errno = EADDRNOTAVAIL;
ret:
	freeaddrinfo(res);
	return len;
}

static int
sock(char *host, char *port, struct sockaddr *addr, socklen_t *alen)
{
	int fd;

	/* From getaddrinfo(3)
	 *   The nodename and servname arguments are either null
	 *   pointers or pointers to null-terminated strings. One or
	 *   both of these two arguments *shall be supplied by the
	 *   application as a non-null pointer.
	 */
	assert(host != NULL || port != NULL);
	if (!(*alen = str2addr(host, port, addr)))
		return -1;

	if ((fd = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1)
		return -1;

	return fd;
}

static int
usock(char *host, char *port)
{
	int fd;
	socklen_t alen;
	struct sockaddr_storage addr;

	if ((fd = sock(host, port, (struct sockaddr*)&addr, &alen)) == -1)
		return -1;
	if ((bind(fd, (struct sockaddr*)&addr, alen)) == -1)
		return -1;

	return fd;
}

static int
dsock(char *host, char *port, int ufd, struct dctx *dctx)
{
	int fd;
	session_t sess;

	memset(&sess, '\0', sizeof(sess));
	if ((fd = sock(host, port, &sess.addr.sa, &sess.size)) == -1)
		return -1;

	dctx->ufd = ufd;
	dctx->dfd = fd;

	if (!(ctx = dtls_new_context(dctx))) {
		errno = ENOMEM;
		return -1;
	}

	dtls_set_handler(ctx, &dtlscb);
	if (dtls_connect(ctx, &sess) < 0) {
		errno = ECONNREFUSED;
		return -1;
	}

	return fd;
}

static void
hdtls(int fd)
{
	ssize_t r;
	session_t sess;
	unsigned char buf[BSIZ];

	memset(&sess, '\0', sizeof(sess));
	sess.size = sizeof(sess.addr);

	if ((r = recvfrom(fd, buf, BUFSIZ, MSG_DONTWAIT,
			&sess.addr.sa, &sess.size)) == -1) {
		fprintf(stderr, "dtls recvfrom failed: %s\n", strerror(errno));
		return;
	}

	/* TODO: what are we supposed to do with the return value? */
	dtls_handle_message(ctx, &sess, buf, r);
}

static void
hudp(int fd)
{
	ssize_t r;
	session_t sess;
	unsigned char buf[BSIZ];

	memset(&sess, '\0', sizeof(sess));
	sess.size = sizeof(sess.addr);

	if ((r = recvfrom(fd, buf, BUFSIZ, MSG_DONTWAIT,
			&sess.addr.sa, &sess.size)) == -1) {
		fprintf(stderr, "udp recvfrom failed: %s\n", strerror(errno));
		return;
	}

	if (dtls_write(ctx, &sess, buf, r) == -1) {
		fprintf(stderr, "dtls_write failed\n");
		return;
	}
}

void
ploop(int ufd, int dfd)
{
	int fd;
	size_t i;
	short ev;
	nfds_t nfds;
	struct pollfd fds[2];

	nfds = sizeof(fds) / sizeof(fds[0]);

	fds[0] = newpollfd(ufd);
	fds[1] = newpollfd(dfd);

	for (;;) {
		if (poll(fds, nfds, -1) == -1)
			err(EXIT_FAILURE, "poll failed");

		for (i = 0; i < nfds; i++) {
			fd = fds[i].fd;
			ev = fds[i].revents;

			if (ev & POLLERR) {
				fprintf(stderr, "Received POLLERR on FD %d\n", fd);
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
	struct dctx ctx;
	int opt, ufd, dfd;
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
	if ((dfd = dsock(daddr, dport, ufd, &ctx)) == -1)
		err(EXIT_FAILURE, "dsock failed");

	ploop(ufd, dfd);
	return EXIT_SUCCESS;
}
