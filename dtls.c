#include <dtls.h>
#include <dtls_debug.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>

#include "dat.h"

/**
 * session_t for the UDP socket client, defined in `dunnel.c`.
 */
extern session_t usess;

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
	if (sendto(dctx->ufd, data, len, MSG_DONTWAIT,
			&usess.addr.sa, usess.size) == -1)
		dtls_alert("Couldn't send %zu bytes to UDP socket\n", len);

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
