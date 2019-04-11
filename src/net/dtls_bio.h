#pragma once
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "dtls.h"

/** OpenSSL BIO agent writer initialization */
int dtls_bio_agent_init(void);

/** OpenSSL BIO agent writer constructor */
BIO *BIO_dtls_agent_new(struct dtls_srtp *dtls);

/** Set the MTU for the BIO agent writer
 *
 * The default starting MTU is 1472, in case fragmentation is needed
 * the OpenSSL DTLS stack automatically decreases it. That said, if
 * you know for sure the MTU in the network Server is deployed in is
 * smaller than that, it makes sense to configure an according value to
 * start from.
 *
 * @param start_mtu The MTU to start from (1472 by default)
 */
void dtls_bio_agent_set_mtu(int start_mtu);

_Static_assert(OPENSSL_VERSION_NUMBER >= 0x10100000L, "OpenSSL version must >= 1.1");
