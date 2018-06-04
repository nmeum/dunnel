#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <netdb.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>

static void
usage(char *progname)
{
	fprintf(stderr, "Usage: %s "
		"-a [ADDR] -p [PORT]"
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
	struct sockaddr addr;

	if ((fd = sock(host, port, &addr, &alen)) == -1)
		return -1;
	if ((bind(fd, &addr, alen)) == -1)
		return -1;

	return fd;
}

/* static int */
/* dsock(char *host, char *port) */
/* { */
/* 	int fd; */
/* 	session_t sess; */
/* 	dtls_context_t *ctx; */

/* 	memset(&sess, '\0', sizeof(sess)); */
/* 	if ((fd = sock(host, port, &sess.addr.sa, &sess.size)) == -1) */
/* 		return -1; */

/* 	if (!(ctx = dtls_new_context(&fd))) { */
/* 		errno = ENOMEM; */
/* 		return -1; */
/* 	} */

/* 	dtls_set_handler(ctx, &dtlscb); */
/* 	if (dtls_connect(ctx, &sess) < 0) { */
/* 		errno = ECONNREFUSED; */
/* 		return -1; */
/* 	} */

/* 	return fd; */
/* } */

int
main(int argc, char **argv)
{
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

	daddr = argv[optind];
	dport = argv[optind + 1];

	if ((ufd = usock(uaddr, (!uport) ? dport : uport)) == -1)
		err(EXIT_FAILURE, "udpsock failed");
}
