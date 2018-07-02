/**
 * DTLS session declared in `dunnel.c`.
 */
extern session_t dsess;

/**
 * session_t for the socket client, defined in `dunnel.c`.
 */
extern session_t csess;

/**
 * DTLS callback declared in `dtls.c`.
 */
extern dtls_handler_t dtlscb;

/**
 * Command line argument from `dunnel.c`.
 */
extern int smode;

/**
 * Struct use for the application data in the dtls_context_t.
 */
struct dctx {
	int ufd; /* FD of the UDP socket. */
	int dfd; /* FD of the DTLS socket. */

	unsigned char *id, *key;
};

/**
 * Enum used to specify which operation should be performed on the usock.
 */
typedef enum {
	SOCK_CONN,
	SOCK_BIND,
} sockop;
