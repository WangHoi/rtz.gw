#include "dtls.h"
#include "dtls-bio.h"
#include "log.h"
#include "rtp_srtp.h"
#include "event_loop.h"
#include "ice.h"
#include <openssl/ssl.h>
#include <openssl/pem.h>
#include <string.h>
#include <srtp2/srtp.h>
#include <inttypes.h>

/* DTLS stuff */
static const char *DTLS_CIPHERS = "HIGH:!aNULL:!MD5:!RC4";

static SSL_CTX *ssl_ctx = NULL;
static X509 *ssl_cert = NULL;
static EVP_PKEY *ssl_key = NULL;
static char local_fingerprint[160];

static int dtls_load_keys(const char *server_pem, const char *server_key, const char *password,
                          X509 **certificate, EVP_PKEY **private_key);
static int dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx);
static void dtls_callback(const SSL *ssl, int where, int ret);

int dtls_srtp_init(const char *server_pem, const char *server_key, const char *password)
{
    ssl_ctx = SSL_CTX_new(DTLS_method());
    if (!ssl_ctx) {
        LLOG(LL_FATAL, "Ops, error creating DTLS context.");
        return -1;
    }
    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, dtls_verify_callback);
    SSL_CTX_set_tlsext_use_srtp(ssl_ctx, "SRTP_AEAD_AES_256_GCM:SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80:SRTP_AES128_CM_SHA1_32");
    if (!server_pem || !server_key) {
        LLOG(LL_FATAL, "DTLS certificate and key must be specified.");
        return -2;
    }
    if (dtls_load_keys(server_pem, server_key, password, &ssl_cert, &ssl_key) != 0)
        return -3;

    if (!SSL_CTX_use_certificate(ssl_ctx, ssl_cert)) {
        LLOG(LL_FATAL, "Certificate error (%s).", ERR_reason_error_string(ERR_get_error()));
        return -4;
    }
    if (!SSL_CTX_use_PrivateKey(ssl_ctx, ssl_key)) {
        LLOG(LL_FATAL, "Certificate key error (%s).", ERR_reason_error_string(ERR_get_error()));
        return -5;
    }
    if (!SSL_CTX_check_private_key(ssl_ctx)) {
        LLOG(LL_FATAL, "Certificate check error (%s).", ERR_reason_error_string(ERR_get_error()));
        return -6;
    }
    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    unsigned int size;
    unsigned char fingerprint[EVP_MAX_MD_SIZE];
    if (X509_digest(ssl_cert, EVP_sha256(), (unsigned char *)fingerprint, &size) == 0) {
        LLOG(LL_FATAL, "Error converting X509 structure (%s).", ERR_reason_error_string(ERR_get_error()));
        return -7;
    }
    char *lfp = (char *)&local_fingerprint;
    unsigned int i = 0;
    for (i = 0; i < size; i++) {
        snprintf(lfp, 4, "%.2X:", fingerprint[i]);
        lfp += 3;
    }
    *(lfp - 1) = 0;
    LLOG(LL_INFO, "Fingerprint of our certificate: %s.", local_fingerprint);
    SSL_CTX_set_cipher_list(ssl_ctx, DTLS_CIPHERS);

    if (dtls_bio_agent_init() < 0) {
        LLOG(LL_FATAL, "Error initializing BIO agent.");
        return -8;
    }

    /* Initialize libsrtp */
    if (srtp_init() != srtp_err_status_ok) {
        LLOG(LL_FATAL, "Ops, error setting up libsrtp?");
        return 5;
    }
    return 0;
}

void dtls_srtp_free(dtls_srtp *dtls)
{
    /* This stack can be destroyed, free all the resources */
    dtls->component = NULL;
    if (dtls->ssl != NULL) {
        SSL_free(dtls->ssl);
        dtls->ssl = NULL;
    }
    /* BIOs are destroyed by SSL_free */
    dtls->read_bio = NULL;
    dtls->write_bio = NULL;
    if (dtls->srtp_valid) {
        if (dtls->srtp_in) {
            srtp_dealloc(dtls->srtp_in);
            dtls->srtp_in = NULL;
        }
        if (dtls->srtp_out) {
            srtp_dealloc(dtls->srtp_out);
            dtls->srtp_out = NULL;
        }
        /* FIXME What about dtls->remote_policy and dtls->local_policy? */
    }
    free(dtls);
}

void dtls_srtp_cleanup()
{
    if (ssl_cert != NULL) {
        X509_free(ssl_cert);
        ssl_cert = NULL;
    }
    if (ssl_key != NULL) {
        EVP_PKEY_free(ssl_key);
        ssl_key = NULL;
    }
    if (ssl_ctx != NULL) {
        SSL_CTX_free(ssl_ctx);
        ssl_ctx = NULL;
    }
}

const char *dtls_get_local_fingerprint()
{
    return local_fingerprint;
}

int dtls_load_keys(const char *server_pem, const char *server_key, const char *password,
                   X509 **certificate, EVP_PKEY **private_key)
{
    FILE *f = NULL;

    f = fopen(server_pem, "r");
    if (!f) {
        LLOG(LL_FATAL, "Error opening certificate file.");
        goto error;
    }
    *certificate = PEM_read_X509(f, NULL, NULL, NULL);
    if (!*certificate) {
        LLOG(LL_FATAL, "PEM_read_X509 failed.");
        goto error;
    }
    fclose(f);

    f = fopen(server_key, "r");
    if (!f) {
        LLOG(LL_FATAL, "Error opening key file.");
        goto error;
    }
    *private_key = PEM_read_PrivateKey(f, NULL, NULL, (void *)password);
    if (!*private_key) {
        LLOG(LL_FATAL, "PEM_read_PrivateKey failed.");
        goto error;
    }
    fclose(f);

    return 0;

error:
    if (*certificate) {
        X509_free(*certificate);
        *certificate = NULL;
    }
    if (*private_key) {
        EVP_PKEY_free(*private_key);
        *private_key = NULL;
    }
    return -1;
}

dtls_srtp *dtls_srtp_create(void *ice_component, dtls_role role)
{
    dtls_srtp *dtls = malloc(sizeof(dtls_srtp));
    memset(dtls, 0, sizeof(dtls_srtp));
    /* Create SSL context, at last */
    dtls->srtp_valid = 0;
    dtls->ssl = SSL_new(ssl_ctx);
    if (!dtls->ssl) {
        LLOG(LL_ERROR, "Error creating DTLS session! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        // free dtls
        return NULL;
    }
    SSL_set_ex_data(dtls->ssl, 0, dtls);
    SSL_set_info_callback(dtls->ssl, dtls_callback);
    dtls->read_bio = BIO_new(BIO_s_mem());
    if (!dtls->read_bio) {
        LLOG(LL_ERROR, "Error creating read BIO! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        //janus_refcount_decrease(&dtls->ref);
        // free dtls
        return NULL;
    }
    BIO_set_mem_eof_return(dtls->read_bio, -1);
    dtls->write_bio = BIO_dtls_agent_new(dtls);
    if (!dtls->write_bio) {
        LLOG(LL_ERROR, "Error creating write BIO! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        // janus_refcount_decrease(&dtls->ref);
        // free dtls
        return NULL;
    }
    SSL_set_bio(dtls->ssl, dtls->read_bio, dtls->write_bio);
    /* The role may change later, depending on the negotiation */
    dtls->dtls_role = role;
    /* https://code.google.com/p/chromium/issues/detail?id=406458
     * Specify an ECDH group for ECDHE ciphers, otherwise they cannot be
     * negotiated when acting as the server. Use NIST's P-256 which is
     * commonly supported.
     */
    EC_KEY *ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (ecdh == NULL) {
        LLOG(LL_ERROR, "Error creating ECDH group! (%s)",
             ERR_reason_error_string(ERR_get_error()));
        //janus_refcount_decrease(&dtls->ref);
        // free dtls
        return NULL;
    }
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_SINGLE_ECDH_USE;
    SSL_set_options(dtls->ssl, flags);
    SSL_set_tmp_ecdh(dtls->ssl, ecdh);
    EC_KEY_free(ecdh);
    dtls->ready = 0;
    dtls->retransmissions = 0;
    /* Done */
    dtls->dtls_connected = 0;
    dtls->component = ice_component;
    return dtls;
}

void dtls_srtp_handshake(dtls_srtp *dtls)
{
    if (dtls == NULL || dtls->ssl == NULL)
        return;
    if (dtls->dtls_state == DTLS_STATE_CREATED) {
        /* Starting the handshake now: enforce the role */
        dtls->dtls_started = zl_hrtimestamp();
        if (dtls->dtls_role == DTLS_ROLE_CLIENT) {
            SSL_set_connect_state(dtls->ssl);
        } else {
            SSL_set_accept_state(dtls->ssl);
        }
        dtls->dtls_state = DTLS_STATE_TRYING;
    }
    SSL_do_handshake(dtls->ssl);
}

void dtls_srtp_incoming_msg(dtls_srtp *dtls, char *buf, uint16_t len)
{
    if (!dtls) {
        LLOG(LL_ERROR, "No DTLS-SRTP stack, no incoming message...");
        return;
    }
    ice_component_t *component = (ice_component_t*)dtls->component;
    if (!component) {
        LLOG(LL_ERROR, "No component, no DTLS...");
        return;
    }
    ice_stream_t *stream = ice_component_get_stream(component);
    if (!stream) {
        LLOG(LL_ERROR, "No stream, no DTLS...");
        return;
    }
    ice_agent_t *handle = ice_stream_get_agent(stream);
    if (!handle) {
        LLOG(LL_ERROR, "No handle/agent, no DTLS...");
        return;
    }
    if (ice_flags_is_set(handle, ICE_HANDLE_WEBRTC_ALERT)) {
        LLOG(LL_WARN, "Alert already triggered, clearing up...");
        return;
    }
    if (!dtls->ssl || !dtls->read_bio) {
        LLOG(LL_ERROR, "No DTLS stuff for component??");
        return;
    }
    if (dtls->dtls_started == 0) {
        /* Handshake not started yet: maybe we're still waiting for the answer and the DTLS role? */
        return;
    }
    int written = BIO_write(dtls->read_bio, buf, len);
    if (written != len) {
        LLOG(LL_WARN, "Only written %d/%d of those bytes on the read BIO...", written, len);
    } else {
        //LLOG(LL_TRACE, "Written %d bytes on the read BIO...", written);
    }
    /* Try to read data */
    char data[1500];	/* FIXME */
    memset(&data, 0, 1500);
    int read = SSL_read(dtls->ssl, &data, 1500);
    //LLOG(LL_TRACE, "   ... and read %d of them from SSL...", read);
    if (read < 0) {
        unsigned long err = SSL_get_error(dtls->ssl, read);
        if (err == SSL_ERROR_SSL) {
            /* Ops, something went wrong with the DTLS handshake */
            char error[200];
            ERR_error_string_n(ERR_get_error(), error, 200);
            LLOG(LL_ERROR, "Handshake error: %s", error);
            return;
        }
    }
    if (ice_flags_is_set(handle, ICE_HANDLE_WEBRTC_STOP)/* || janus_is_stopping()*/) {
        /* DTLS alert triggered, we should end it here */
        LLOG(LL_TRACE, "Forced to stop it here...");
        return;
    }
    if (!SSL_is_init_finished(dtls->ssl)) {
        /* Nothing else to do for now */
        //LLOG(LL_TRACE, "Initialization not finished yet...");
        return;
    }
    if (dtls->ready) {
        /* There's data to be read? */
        //LLOG(LL_TRACE, "Any data available?");
        if (read > 0) {
            LLOG(LL_WARN, "Data available but Data Channels support disabled...");
        }
    } else {
        //LLOG(LL_TRACE, "DTLS established, yay!");
        /* Check the remote fingerprint */
        X509 *rcert = SSL_get_peer_certificate(dtls->ssl);
        if (!rcert) {
            LLOG(LL_ERROR, "No remote certificate?? (%s)", 
                 ERR_reason_error_string(ERR_get_error()));
        } else {
            unsigned int rsize;
            unsigned char rfingerprint[EVP_MAX_MD_SIZE];
            char remote_fingerprint[160];
            char *rfp = (char *)&remote_fingerprint;
            sbuf_t *remote_hashing = ice_stream_get_remote_hashing(stream);
            sbuf_t *jsep_remote_fingerprint = ice_stream_get_remote_fingerprint(stream);
            const char *digest_method;
            if (!strcasecmp(remote_hashing->data, "sha-1")) {
                //LLOG(LL_TRACE, "Computing sha-1 fingerprint of remote certificate...");
                digest_method = "sha-1";
                X509_digest(rcert, EVP_sha1(), rfingerprint, &rsize);
            } else {
                //LLOG(LL_TRACE, "Computing sha-256 fingerprint of remote certificate...");
                digest_method = "sha-256";
                X509_digest(rcert, EVP_sha256(), rfingerprint, &rsize);
            }
            X509_free(rcert);
            rcert = NULL;
            unsigned int i = 0;
            for (i = 0; i < rsize; i++) {
                snprintf(rfp, 4, "%.2X:", rfingerprint[i]);
                rfp += 3;
            }
            *(rfp - 1) = 0;
            //LLOG(LL_TRACE, "Remote fingerprint (%s) of the client is %s",
            //     digest_method, remote_fingerprint);
            if (sbuf_empty(jsep_remote_fingerprint) || !strcasecmp("(none)", jsep_remote_fingerprint->data)
                || !strcasecmp(remote_fingerprint, jsep_remote_fingerprint->data)) {

                //LLOG(LL_TRACE, "Fingerprint is a match!");
                dtls->dtls_state = DTLS_STATE_CONNECTED;
                dtls->dtls_connected = zl_hrtimestamp();
            } else {
                /* FIXME NOT a match! MITM? */
                LLOG(LL_ERROR, "Fingerprint is NOT a match! got %s, expected %s", remote_fingerprint, jsep_remote_fingerprint->data);
                dtls->dtls_state = DTLS_STATE_FAILED;
                goto done;
            }
            if (dtls->dtls_state == DTLS_STATE_CONNECTED) {
                /* Which SRTP profile is being negotiated? */
                SRTP_PROTECTION_PROFILE *srtp_profile = SSL_get_selected_srtp_profile(dtls->ssl);
                if (srtp_profile == NULL) {
                    /* Should never happen, but just in case... */
                    LLOG(LL_ERROR, "No SRTP profile selected...");
                    dtls->dtls_state = DTLS_STATE_FAILED;
                    goto done;
                }
                //LLOG(LL_TRACE, "SRTP Profile %s", srtp_profile->name);
                int key_length = 0, salt_length = 0, master_length = 0;
                switch (srtp_profile->id) {
                case SRTP_AES128_CM_SHA1_80:
                case SRTP_AES128_CM_SHA1_32:
                    key_length = SRTP_MASTER_KEY_LENGTH;
                    salt_length = SRTP_MASTER_SALT_LENGTH;
                    master_length = SRTP_MASTER_LENGTH;
                    break;
                case SRTP_AEAD_AES_256_GCM:
                    key_length = SRTP_AESGCM256_MASTER_KEY_LENGTH;
                    salt_length = SRTP_AESGCM256_MASTER_SALT_LENGTH;
                    master_length = SRTP_AESGCM256_MASTER_LENGTH;
                    break;
                case SRTP_AEAD_AES_128_GCM:
                    key_length = SRTP_AESGCM128_MASTER_KEY_LENGTH;
                    salt_length = SRTP_AESGCM128_MASTER_SALT_LENGTH;
                    master_length = SRTP_AESGCM128_MASTER_LENGTH;
                    break;
                default:
                    /* Will never happen? */
                    LLOG(LL_WARN, "Unsupported SRTP profile %lu", srtp_profile->id);
                    break;
                }
                //LLOG(LL_TRACE, "Key/Salt/Master: %d/%d/%d", master_length, key_length, salt_length);
                /* Complete with SRTP setup */
                unsigned char material[master_length * 2];
                unsigned char *local_key, *local_salt, *remote_key, *remote_salt;
                /* Export keying material for SRTP */
                if (!SSL_export_keying_material(dtls->ssl, material, master_length * 2, "EXTRACTOR-dtls_srtp", 19, NULL, 0, 0)) {
                    /* Oops... */
                    LLOG(LL_ERROR, "Oops, couldn't extract SRTP keying material for component in stream?? (%s)",
                         ERR_reason_error_string(ERR_get_error()));
                    goto done;
                }
                /* Key derivation (http://tools.ietf.org/html/rfc5764#section-4.2) */
                if (dtls->dtls_role == DTLS_ROLE_CLIENT) {
                    local_key = material;
                    remote_key = local_key + key_length;
                    local_salt = remote_key + key_length;
                    remote_salt = local_salt + salt_length;
                } else {
                    remote_key = material;
                    local_key = remote_key + key_length;
                    remote_salt = local_key + key_length;
                    local_salt = remote_salt + salt_length;
                }
                /* Build master keys and set SRTP policies */
                /* Remote (inbound) */
                switch (srtp_profile->id) {
                case SRTP_AES128_CM_SHA1_80:
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(dtls->remote_policy.rtp));
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(dtls->remote_policy.rtcp));
                    break;
                case SRTP_AES128_CM_SHA1_32:
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(dtls->remote_policy.rtp));
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(dtls->remote_policy.rtcp));
                    break;
                case SRTP_AEAD_AES_256_GCM:
                    srtp_crypto_policy_set_aes_gcm_256_16_auth(&(dtls->remote_policy.rtp));
                    srtp_crypto_policy_set_aes_gcm_256_16_auth(&(dtls->remote_policy.rtcp));
                    break;
                case SRTP_AEAD_AES_128_GCM:
                    srtp_crypto_policy_set_aes_gcm_128_16_auth(&(dtls->remote_policy.rtp));
                    srtp_crypto_policy_set_aes_gcm_128_16_auth(&(dtls->remote_policy.rtcp));
                    break;
                default:
                    /* Will never happen? */
                    LLOG(LL_WARN, "Unsupported SRTP profile %s", srtp_profile->name);
                    break;
                }
                dtls->remote_policy.ssrc.type = ssrc_any_inbound;
                unsigned char remote_policy_key[master_length];
                dtls->remote_policy.key = (unsigned char *)&remote_policy_key;
                memcpy(dtls->remote_policy.key, remote_key, key_length);
                memcpy(dtls->remote_policy.key + key_length, remote_salt, salt_length);
                dtls->remote_policy.window_size = 128;
                dtls->remote_policy.allow_repeat_tx = 0;
                dtls->remote_policy.next = NULL;
                /* Local (outbound) */
                switch (srtp_profile->id) {
                case SRTP_AES128_CM_SHA1_80:
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(dtls->local_policy.rtp));
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(dtls->local_policy.rtcp));
                    break;
                case SRTP_AES128_CM_SHA1_32:
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32(&(dtls->local_policy.rtp));
                    srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&(dtls->local_policy.rtcp));
                    break;
                case SRTP_AEAD_AES_256_GCM:
                    srtp_crypto_policy_set_aes_gcm_256_16_auth(&(dtls->local_policy.rtp));
                    srtp_crypto_policy_set_aes_gcm_256_16_auth(&(dtls->local_policy.rtcp));
                    break;
                case SRTP_AEAD_AES_128_GCM:
                    srtp_crypto_policy_set_aes_gcm_128_16_auth(&(dtls->local_policy.rtp));
                    srtp_crypto_policy_set_aes_gcm_128_16_auth(&(dtls->local_policy.rtcp));
                    break;
                default:
                    /* Will never happen? */
                    LLOG(LL_WARN, "Unsupported SRTP profile %s", srtp_profile->name);
                    break;
                }
                dtls->local_policy.ssrc.type = ssrc_any_outbound;
                unsigned char local_policy_key[master_length];
                dtls->local_policy.key = (unsigned char *)&local_policy_key;
                memcpy(dtls->local_policy.key, local_key, key_length);
                memcpy(dtls->local_policy.key + key_length, local_salt, salt_length);
                dtls->local_policy.window_size = 128;
                dtls->local_policy.allow_repeat_tx = 0;
                dtls->local_policy.next = NULL;
                /* Create SRTP sessions */
                srtp_err_status_t res = srtp_create(&(dtls->srtp_in), &(dtls->remote_policy));
                if (res != srtp_err_status_ok) {
                    /* Something went wrong... */
                    LLOG(LL_ERROR, "Oops, error creating inbound SRTP session for component in stream??");
                    LLOG(LL_ERROR, "  -- %d (%s)\n", res, rtz_srtp_error_str(res));
                    goto done;
                }
                //LLOG(LL_TRACE, "Created inbound SRTP session for component in stream");
                res = srtp_create(&(dtls->srtp_out), &(dtls->local_policy));
                if (res != srtp_err_status_ok) {
                    /* Something went wrong... */
                    LLOG(LL_ERROR, "Oops, error creating outbound SRTP session for component in stream??");
                    LLOG(LL_ERROR, "  -- %d (%s)", res, rtz_srtp_error_str(res));
                    goto done;
                }
                dtls->srtp_profile = srtp_profile->id;
                dtls->srtp_valid = 1;
                //LLOG(LL_TRACE, "Created outbound SRTP session for component in stream");
                dtls->ready = 1;
            }
done:
            if (!ice_flags_is_set(handle, ICE_HANDLE_WEBRTC_ALERT) && dtls->srtp_valid) {
                /* Handshake successfully completed */
                ice_dtls_handshake_done(handle, component);
            } else {
                /* Something went wrong in either DTLS or SRTP... */
                dtls_callback(dtls->ssl, SSL_CB_ALERT, 0);
                ice_flags_set(handle, ICE_HANDLE_WEBRTC_CLEANING);
            }
        }
    }
}

void dtls_srtp_send_alert(dtls_srtp *dtls) {
    /* Send alert */
    if (dtls != NULL && dtls->ssl != NULL) {
        SSL_shutdown(dtls->ssl);
    }
}

void dtls_srtp_destroy(dtls_srtp *dtls)
{
    if (!dtls || dtls->destroyed)
        return;
    dtls->ready = 0;
    dtls->retransmissions = 0;
}

/** DTLS alert callback */
void dtls_callback(const SSL *ssl, int where, int ret)
{
    /* We only care about alerts */
    //LLOG(LL_TRACE, "dtls callback where=%04x ret=%d", where, ret);
    if (!(where & SSL_CB_ALERT)) {
        return;
    }
    dtls_srtp *dtls = SSL_get_ex_data(ssl, 0);
    if (!dtls) {
        LLOG(LL_ERROR, "No DTLS session related to this alert...");
        return;
    }
    ice_component_t *component = dtls->component;
    if (component == NULL) {
        LLOG(LL_ERROR, "No ICE component related to this alert...");
        return;
    }
    ice_stream_t *stream = ice_component_get_stream(component);
    if (!stream) {
        LLOG(LL_ERROR, "No ICE stream related to this alert...");
        return;
    }
    ice_agent_t *handle = ice_stream_get_agent(stream);
    if (!handle) {
        LLOG(LL_ERROR, "No ICE handle related to this alert...");
        return;
    }
    LLOG(LL_TRACE, "DTLS alert triggered on stream (component), closing...");
    ice_webrtc_hangup(handle, "DTLS alert");
}

int dtls_retry(void *stack)
{
    LLOG(LL_WARN, "dtls_retry not implemented!");
    return 0;
#if 0
    dtls_srtp *dtls = (dtls_srtp *)stack;
    if (dtls == NULL)
        return 0;
    ice_component_t *component = (ice_component_t *)dtls->component;
    if (component == NULL)
        return 0;
    ice_stream_t *stream = component->stream;
    if (!stream)
        goto stoptimer;

    janus_ice_handle *handle = stream->handle;
    if (!handle)
        goto stoptimer;
    if (janus_flags_is_set(&handle->webrtc_flags, JANUS_ICE_HANDLE_WEBRTC_STOP))
        goto stoptimer;
    if (dtls->dtls_state == DTLS_STATE_CONNECTED) {
        LLOG(LL_TRACE, "DTLS already set up, disabling retransmission timer!");
        goto stoptimer;
    }
    if (zl_hrtime() - dtls->dtls_started >= 20 * ZL_USEC_PER_SEC) {
        /* FIXME Should we really give up after 20 seconds waiting for DTLS? */
        LLOG(LL_ERROR, "DTLS taking too much time for component in stream...");
        ice_webrtc_hangup(handle, "DTLS timeout");
        goto stoptimer;
    }
    struct timeval timeout = { 0 };
    if (DTLSv1_get_timeout(dtls->ssl, &timeout) == 0) {
        /* failed to get timeout. try again on next iter */
        return 1;
    }
    uint64_t timeout_value = timeout.tv_sec * 1000 + timeout.tv_usec / 1000;
    LLOG(LL_TRACE, "DTLSv1_get_timeout: %"SCNu64"\n", timeout_value);
    if (timeout_value == 0) {
        dtls->retransmissions++;
        LLOG(LOG_VERB, "[%"SCNu64"] DTLS timeout on component %d of stream %d, retransmitting\n", handle->handle_id, component->component_id, stream->stream_id);
        /* Retransmit the packet */
        DTLSv1_handle_timeout(dtls->ssl);
    }
    return 1;

stoptimer:
    if (component->dtlsrt_source != NULL) {
        g_source_destroy(component->dtlsrt_source);
        g_source_unref(component->dtlsrt_source);
        component->dtlsrt_source = NULL;
    }
    return 0;
#endif
}

const char *get_dtls_srtp_state(dtls_state state)
{
    switch (state) {
    case DTLS_STATE_CREATED:
        return "created";
    case DTLS_STATE_TRYING:
        return "trying";
    case DTLS_STATE_CONNECTED:
        return "connected";
    case DTLS_STATE_FAILED:
        return "failed";
    default:
        return NULL;
    }
    return NULL;
}

const char *get_dtls_srtp_role(dtls_role role)
{
    switch (role) {
    case DTLS_ROLE_ACTPASS:
        return "actpass";
    case DTLS_ROLE_SERVER:
        return "passive";
    case DTLS_ROLE_CLIENT:
        return "active";
    default:
        return NULL;
    }
    return NULL;
}

const char *get_dtls_srtp_profile(int profile)
{
    switch (profile) {
    case SRTP_AES128_CM_SHA1_80:
        return "SRTP_AES128_CM_SHA1_80";
    case SRTP_AES128_CM_SHA1_32:
        return "SRTP_AES128_CM_SHA1_32";
    case SRTP_AEAD_AES_256_GCM:
        return "SRTP_AEAD_AES_256_GCM";
    case SRTP_AEAD_AES_128_GCM:
        return "SRTP_AEAD_AES_128_GCM";
    default:
        return NULL;
    }
    return NULL;
}

/** DTLS certificate verification callback */
int dtls_verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
    /* We just use the verify_callback to request a certificate from the client */
    return 1;
}
