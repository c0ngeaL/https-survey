#ifndef FUNC_H
#define FUNC_H

#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <stdbool.h>
#include <stddef.h>
#include <pthread.h>

#define MAX_CIPHERS 32
#define MAX_CIPHER_NAME_LEN 128
#define MAX_VERSION_LEN 16




typedef struct {
    char* name;
    int bits;
    char* version;
    bool is_supported;
    bool is_rsa;
} CipherInfo;

typedef struct {
    CipherInfo* ciphers;
    size_t count;
    size_t capacity;
} CipherList;

typedef struct {
    bool sslv2;
    bool sslv3;
    bool tlsv1;
    bool tlsv1_1;
    bool tlsv1_2;
    bool tlsv1_3;
} TLSProtocolSupport;

typedef struct {
    const char* host;
    size_t port;
} TLSConnectionParams;

typedef struct {
    TLSConnectionParams params;
    TLSProtocolSupport protocol_support;
    STACK_OF(SSL_CIPHER)* ciphers;
    X509* cert;
    const char* error;
    SSL* ssl;
} TLSCheckResult;
typedef struct {
    const char* host;
    int port;
    const char* cipher_name;
    int tls_version_idx;
    CipherList* list;
} CipherTask;

void print_hex(const unsigned char* data, size_t len);
bool check_heartbleed(const char* host, int port);
CipherList get_supported_ciphers(const char* host, int port);
void free_cipher_list(CipherList* list);
void print_ciphers(const CipherList* list);
void print_cert_info(X509* cert);
void print_protocol_support(TLSProtocolSupport* support);
void check_tls_server(const char* host, size_t port, TLSCheckResult* result);
void init_openssl(void);
void cleanup_openssl(void);

#endif
