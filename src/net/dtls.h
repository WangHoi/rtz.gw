#pragma once
#include <openssl/ssl.h>
#include <srtp2/srtp.h>

/** DTLS roles */
typedef enum dtls_role {
    DTLS_ROLE_ACTPASS = -1,
    DTLS_ROLE_SERVER,
    DTLS_ROLE_CLIENT,
} dtls_role;

/** DTLS state */
typedef enum dtls_state {
    DTLS_STATE_FAILED = -1,
    DTLS_STATE_CREATED,
    DTLS_STATE_TRYING,
    DTLS_STATE_CONNECTED,
} dtls_state;

/** DTLS-SRTP handle */
typedef struct dtls_srtp {
    /** Opaque pointer to the component this DTLS-SRTP context belongs to */
    void *component;
    /** DTLS role of the server for this stream: 1=client, 0=server */
    dtls_role dtls_role;
    /** DTLS state of this component: -1=failed, 0=nothing, 1=trying, 2=connected */
    dtls_state dtls_state;
    /** Monotonic time of when the DTLS handshake has started */
    int64_t dtls_started;
    /** Monotonic time of when the DTLS state has switched to connected */
    int64_t dtls_connected;
    /** SSL context used for DTLS for this component */
    SSL *ssl;
    /** Read BIO (incoming DTLS data) */
    BIO *read_bio;
    /** Write BIO (outgoing DTLS data) */
    BIO *write_bio;
    /** Whether SRTP has been correctly set up for this component or not */
    int srtp_valid;
    /** The SRTP profile currently in use */
    int srtp_profile;
    /** libsrtp context for incoming SRTP packets */
    srtp_t srtp_in;
    /** libsrtp context for outgoing SRTP packets */
    srtp_t srtp_out;
    /** libsrtp policy for incoming SRTP packets */
    srtp_policy_t remote_policy;
    /** libsrtp policy for outgoing SRTP packets */
    srtp_policy_t local_policy;
    /** Whether this DTLS stack is now ready to be used for messages as well (e.g., SCTP encapsulation) */
    int ready;
    /** The number of retransmissions that have occurred for this DTLS instance so far */
    int retransmissions;
    /** Flag to check if this instance has been destroyed */
    int destroyed;
} dtls_srtp;

/** DTLS stuff initialization
 *  @param server_pem Path to the certificate to use
 *  @param server_key Path to the key to use
 *  @param password Password needed to use the key, if any
 *  @return 0 in case of success, a negative integer on errors */
int dtls_srtp_init(const char *server_pem, const char *server_key, const char *password);
/** Cleanup DTLS stuff before exiting */
void dtls_srtp_cleanup();
/** Return a string representation (SHA-256) of the certificate fingerprint */
const char *dtls_get_local_fingerprint();

/** Create a dtls_srtp instance
 *  @param component Opaque pointer to the component owning that will use the stack
 *  @param role The role of the DTLS stack (client/server)
 *  @return A new dtls_srtp instance if successful, NULL otherwise */
dtls_srtp *dtls_srtp_create(void *component, dtls_role role);
/** Free a dtls_srtp instance */
void dtls_srtp_free(dtls_srtp *dtls);
/** Start a DTLS handshake
 * @param dtls The dtls_srtp instance to start the handshake on */
void dtls_srtp_handshake(dtls_srtp *dtls);
/** Handle an incoming DTLS message
 * @param dtls The dtls_srtp instance to start the handshake on
 * @param buf The DTLS message data
 * @param len The DTLS message data lenght */
void dtls_srtp_incoming_msg(dtls_srtp *dtls, char *buf, uint16_t len);
/** Send an alert on a dtls_srtp instance
 * @param dtls The dtls_srtp instance to send the alert on */
void dtls_srtp_send_alert(dtls_srtp *dtls);
/** Destroy a dtls_srtp instance
 * @param dtls The dtls_srtp instance to destroy */
void dtls_srtp_destroy(dtls_srtp *dtls);

/** DTLS retransmission timer
 * \details As libnice is going to actually send and receive data, OpenSSL cannot handle retransmissions by itself: this timed callback (g_source_set_callback) deals with this.
 * @param stack Opaque pointer to the dtls_srtp instance to use
 * @return true if a retransmission is still needed, false otherwise */
int dtls_retry(void *stack);

/** Helper method to get a string representation of a DTLS state
 * @param state The DTLS state
 * @return A string representation of the state */
const char *get_dtls_srtp_state(dtls_state state);

/** Helper method to get a string representation of a DTLS role
 * @param role The DTLS role
 * @return A string representation of the role */
const char *get_dtls_srtp_role(dtls_role role);

/** Helper method to get a string representation of an SRTP profile
 * @param profile The SRTP profile as exported by a DTLS-SRTP handshake
 * @return A string representation of the profile */
const char *get_dtls_srtp_profile(int profile);

SSL_CTX *dtls_srtp_get_ssl_ctx();
