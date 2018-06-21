#include <dtls.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "dat.h"

static socklen_t
str2addr(char *host, char *port, struct sockaddr *dest)
{
	socklen_t len;
	struct addrinfo hint, *res, *r;

	memset(&hint, '\0', sizeof(hint));
	hint.ai_family = AF_UNSPEC;
	hint.ai_socktype = SOCK_DGRAM;

	if (getaddrinfo(host, port, &hint, &res)) {
		errno = EAFNOSUPPORT;
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
	 *   both of these two arguments shall be supplied by the
	 *   application as a non-null pointer.
	 */
	assert(host != NULL || port != NULL);
	if (!(*alen = str2addr(host, port, addr)))
		return -1;

	if ((fd = socket(addr->sa_family, SOCK_DGRAM, 0)) == -1)
		return -1;

	return fd;
}

int
usock(char *host, char *port, sockop op)
{
	int fd;
	socklen_t alen;
	struct sockaddr_storage addr;

	if ((fd = sock(host, port, (struct sockaddr*)&addr, &alen)) == -1)
		return -1;

	switch (op) {
	case SOCK_CONN:
		if ((connect(fd, (struct sockaddr*)&addr, alen)) == -1)
			return -1;
		break;
	case SOCK_BIND:
		if ((bind(fd, (struct sockaddr*)&addr, alen)) == -1)
			return -1;
		break;
	default: /* unknown operation */
		errno = EINVAL;
		return -1;
	}

	return fd;
}

dtls_context_t*
dsock(char *host, char *port, int ufd, sockop op)
{
	int fd;
	struct dctx *dctx;
	dtls_context_t *ctx;

	if (!(dctx = malloc(sizeof(*dctx))))
		return NULL;

	memset(&dsess, '\0', sizeof(dsess));
	if ((fd = sock(host, port, &dsess.addr.sa, &dsess.size)) == -1)
		return NULL;

	dctx->ufd = ufd;
	dctx->dfd = fd;

	if (!(ctx = dtls_new_context(dctx))) {
		errno = ENOMEM;
		return NULL;
	}

	dtls_set_handler(ctx, &dtlscb);
	switch (op) {
	case SOCK_CONN:
		if (dtls_connect(ctx, &dsess) < 0) {
			errno = ECONNREFUSED;
			return NULL;
		}
		break;
	case SOCK_BIND:
		if (bind(dctx->dfd, (struct sockaddr*)&dsess.addr.sa, dsess.size) == -1)
			return NULL;
		break;
	default: /* unknown operation */
		errno = EINVAL;
		return NULL;
	}

	return ctx;
}
