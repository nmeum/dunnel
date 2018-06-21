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
	ssize_t ret;
	struct dctx *dctx;

	dctx = dtls_get_app_data(ctx);

	ret = send(dctx->ufd, data, len, MSG_DONTWAIT);
	if (ret == -1) {
		if (errno == EDESTADDRREQ) {
			/* Running in client mode, send to last client. */
			if (csess.size <= 0) {
				dtls_alert("csess wasn't set\n");
				return 0;
			}

			if (sendto(dctx->ufd, data, len, MSG_DONTWAIT,
					&csess.addr.sa, csess.size) == -1)
				dtls_alert("Couldn't send to UDP socket: %s\n", strerror(errno));
		} else {
			dtls_alert("Couldn't send to default address: %s\n", strerror(errno));
		}
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
