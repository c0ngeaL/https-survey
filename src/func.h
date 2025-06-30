#ifndef FUNC_H
#define FUNC_H

#include <openssl/ssl.h>
#include <openssl/x509v3.h>



typedef struct {
    unsigned int sslv2 : 1;
    unsigned int sslv3 : 1;
    unsigned int tlsv1 : 1;
    unsigned int tlsv1_1 : 1;
    unsigned int tlsv1_2 : 1;
    unsigned int tlsv1_3 : 1;
} TLSProtocolSupport;
//Parameters of connection
typedef struct {
    const char *host;
    int port;
} TLSConnectionParams;

typedef struct {
    TLSConnectionParams params;
    TLSProtocolSupport protocol_support;
    STACK_OF(SSL_CIPHER) *ciphers;
    X509 *cert;
    SSL* ssl;
} TLSCheckResult;

void print_hex(const unsigned char *data, size_t len);
void print_ciphers_from_stack(STACK_OF(SSL_CIPHER) *ciphers);
void print_cert_info(X509 *cert);
void print_protocol_support(TLSProtocolSupport *support);
TLSCheckResult check_tls_server(const char *host, int port);
void init_openssl();
void cleanup_openssl();

#endif

