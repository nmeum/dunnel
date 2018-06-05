/**
 * DTLS session declared in `dunnel.c`.
 */
extern session_t dsess;

/**
 * DTLS callback declared in `dtls.c`.
 */
extern dtls_handler_t dtlscb;

/**
 * Struct use for the application data in the dtls_context_t.
 */
struct dctx {
	int ufd; /* FD of the UDP socket. */
	int dfd; /* FD of the DTLS socket. */
};
