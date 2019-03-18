#include "dtls_bio.h"
#include "log.h"
#include "ice.h"

/* Starting MTU value for the DTLS BIO agent writer */
static int mtu = 1200;

void dtls_bio_agent_set_mtu(int start_mtu)
{
    if (start_mtu < 0) {
        LLOG(LL_ERROR, "Invalid MTU...");
        return;
    }
    mtu = start_mtu;
    LLOG(LL_TRACE, "Setting starting MTU in the DTLS BIO writer: %d.", mtu);
}

/* BIO implementation */
static int dtls_bio_agent_write(BIO *h, const char *buf, int num);
static long dtls_bio_agent_ctrl(BIO *h, int cmd, long arg1, void *arg2);
static int dtls_bio_agent_new(BIO *h);
static int dtls_bio_agent_free(BIO *data);

/* BIO initialization */
static BIO_METHOD *dtls_bio_agent_methods = NULL;

int dtls_bio_agent_init()
{
    dtls_bio_agent_methods = BIO_meth_new(BIO_TYPE_BIO, "ice agent writer");
    if (!dtls_bio_agent_methods) {
        return -1;
    }
    BIO_meth_set_write(dtls_bio_agent_methods, dtls_bio_agent_write);
    BIO_meth_set_ctrl(dtls_bio_agent_methods, dtls_bio_agent_ctrl);
    BIO_meth_set_create(dtls_bio_agent_methods, dtls_bio_agent_new);
    BIO_meth_set_destroy(dtls_bio_agent_methods, dtls_bio_agent_free);
    return 0;
}

static BIO_METHOD *BIO_dtls_agent_method()
{
    return dtls_bio_agent_methods;
}

BIO *BIO_dtls_agent_new(struct dtls_srtp *dtls)
{
    BIO* bio = BIO_new(BIO_dtls_agent_method());
    if (!bio)
        return NULL;

    BIO_set_data(bio, dtls);
    return bio;
}

static int dtls_bio_agent_new(BIO *bio)
{
    BIO_set_init(bio, 1);
    BIO_set_data(bio, NULL);
    BIO_set_shutdown(bio, 0);
    return 1;
}

static int dtls_bio_agent_free(BIO *bio)
{
    if (!bio)
        return 0;
    BIO_set_data(bio, NULL);
    return 1;
}

static int dtls_bio_agent_write(BIO *bio, const char *in, int inl)
{
    //LLOG(LL_TRACE, "dtls_bio_agent_write: %p, %d.", in, inl);
    /* Forward data to the write BIO */
    if (inl <= 0) {
        /* ... unless the size is negative or zero */
        LLOG(LL_WARN, "dtls_bio_agent_write failed: negative size (%d).", inl);
        return inl;
    }
    dtls_srtp *dtls = BIO_get_data(bio);
    if (!dtls) {
        LLOG(LL_ERROR, "No DTLS-SRTP stack, no DTLS bridge...");
        return -1;
    }

    ice_component_t *component = (ice_component_t*)dtls->component;
    if (!component) {
        LLOG(LL_ERROR, "No component, no DTLS bridge...");
        return -1;
    }
    ice_stream_t *stream = ice_component_get_stream(component);
    if (!stream) {
        LLOG(LL_ERROR, "No stream, no DTLS bridge...");
        return -1;
    }
    ice_agent_t *handle = ice_stream_get_agent(stream);
    if (!handle || !dtls->write_bio) {
        LLOG(LL_ERROR, "No handle/agent/bio, no DTLS bridge...");
        return -1;
    }
    if (inl > 1500) {
        /* FIXME Just a warning for now, this will need to be solved with proper fragmentation */
        LLOG(LL_WARN, "The DTLS stack with packet size %d exceeds MTU, dropped!", inl);
    }
    ice_send_dtls(handle, in, inl);
    /* Update stats (TODO Do the same for the last second window as well)
     * FIXME: the Data stats includes the bytes used for the handshake */
    //if (bytes > 0) {
    //    component->out_stats.data.packets++;
    //    component->out_stats.data.bytes += inl;
    //}
    return inl;
}

static long dtls_bio_agent_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    switch (cmd) {
    case BIO_CTRL_FLUSH:
        /* The OpenSSL library needs this */
        return 1;
    case BIO_CTRL_DGRAM_QUERY_MTU:
        /* Let's force the MTU that was configured */
        //LLOG(LL_TRACE, "Advertising MTU: %d.", mtu);
        return mtu;
    case BIO_CTRL_WPENDING:
    case BIO_CTRL_PENDING:
        return 0L;
    default:
        /*LLOG(LL_TRACE, "dtls_bio_agent_ctrl: %d.", cmd)*/;
    }
    return 0;
}
