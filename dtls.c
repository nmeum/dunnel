#include <dtls.h>
#include <dtls_debug.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "dat.h"

static int
dwrite(struct dtls_context_t *ctx, session_t *sess, uint8 *data, size_t len)
{
	struct dctx *dctx;

	dctx = dtls_get_app_data(ctx);
	return sendto(dctx->dfd, data, len, MSG_DONTWAIT,
		&sess->addr.sa, sess->size);
}

static int
dread(struct dtls_context_t *ctx, session_t *sess, uint8 *data, size_t len)
{
	(void)sess;
	struct dctx *dctx;

	dctx = dtls_get_app_data(ctx);
	if (smode) {
		/* in server mode connect(3) is called on the UDP socket up
		 * on creation thus we don't need to specify an address. */
		if (send(dctx->ufd, data, len, MSG_DONTWAIT) == -1)
			dtls_alert("send failed in dread: %s\n", strerror(errno));
	} else {
		/* in client mode csess should contain the address of
		 * the client from which we last received a datagram. */
		if (csess.size <= 0) {
			dtls_alert("Didn't receive a datagram from a client yet, "
				"discarding received DTLS message\n");
			return 0;
		}

		if (sendto(dctx->ufd, data, len, MSG_DONTWAIT,
				&csess.addr.sa, csess.size) == -1)
			dtls_alert("sendto failed in dread: %s\n", strerror(errno));
	}

	/* I have no idea why this function prototype has a return value
	 * `tests/dtls-client.c` returns 0 here so lets do that as well. */
	return 0;
}

static int
dpsk(struct dtls_context_t *ctx, const session_t *sess, dtls_credentials_type_t type,
	const unsigned char *id, size_t ilen, unsigned char *res, size_t rlen)
{
	(void)ctx;
	(void)sess;
	(void)type;
	(void)id;
	(void)ilen;
	(void)rlen;

	memcpy(res, "foobar", 6);
	return 6;
}

dtls_handler_t dtlscb = {
  .write = dwrite,
  .read  = dread,
  .event = NULL,
  .get_psk_info = dpsk
};
