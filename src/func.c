#include "func.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
void print_ciphers_from_stack(STACK_OF(SSL_CIPHER) *ciphers) {
    if ( !ciphers) {
        fprintf(stderr, "Cipher stack is empty\n");
        return;
    }
    const int count = sk_SSL_CIPHER_num(ciphers);
    if (count <= 0) {
        printf("No ciphers available!\n");
        sk_SSL_CIPHER_free(ciphers);
        return;
    }

    printf("\nAvailable ciphers (%d):\n", count);
    printf("%-45s | %-8s | %-15s\n", "Cipher Name", "Bits", "Protocol");
    printf("\n");
    for (int i = 0; i < count; i++) {
        const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);
        if (cipher) {
            printf("%-45s | %-8d | %-15s\n",
                     SSL_CIPHER_get_name(cipher),
                   SSL_CIPHER_get_bits(cipher, NULL),
                   SSL_CIPHER_get_version(cipher),
                   SSL_CIPHER_get_auth_nid(cipher) == NID_auth_rsa ? "RSA" : "Other");
        }
    }
}
//this for serial number for x509
void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}
//prints the main information about X509
void print_cert_info(X509 *cert) {
    if (!cert) return;

    printf("Certificate:\n");

    // Subject
    X509_NAME *subject = X509_get_subject_name(cert);
    printf("  Subject: %s\n", X509_NAME_oneline(subject, NULL, 0));

    // Issuer
    X509_NAME *issuer = X509_get_issuer_name(cert);
    printf("  Issuer: %s\n", X509_NAME_oneline(issuer, NULL, 0));

    // Validity
    const ASN1_TIME *not_before = X509_get0_notBefore(cert);
    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    printf("  Valid From: %.*s\n", ASN1_STRING_length(not_before), ASN1_STRING_get0_data(not_before));
    printf("  Valid Until: %.*s\n", ASN1_STRING_length(not_after), ASN1_STRING_get0_data(not_after));

    // Serial
    const ASN1_INTEGER *serial = X509_get0_serialNumber(cert);
    printf("  Serial: ");
    print_hex(ASN1_STRING_get0_data(serial), ASN1_STRING_length(serial));
}
//supported TLS
void print_protocol_support(TLSProtocolSupport *support) {
    printf("TLS/SSL  support:\n");
    printf("  SSL v2: %s\n", support->sslv2 ? "+" : "-");
    printf("  SSL v3: %s\n", support->sslv3 ? "+" : "-");
    printf("  TLS v1.0: %s\n", support->tlsv1 ? "+" : "-");
    printf("  TLS v1.1: %s\n", support->tlsv1_1 ? "+" : "-");
    printf("  TLS v1.2: %s\n", support->tlsv1_2 ? "+" : "-");
    printf("  TLS v1.3: %s\n", support->tlsv1_3 ? "+" : "-");
}

void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

void check_tls_server(const char *host, int port, TLSCheckResult *result) {
    const time_t start_time = time(NULL);
    const int TIMEOUT_SEC = 10;
    if (!result) return;

    // Initialize the result structure
    memset(result, 0, sizeof(TLSCheckResult));
    result->params.host = host;
    result->params.port = port;

    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    BIO *bio = NULL;

    const int protocols[] = {
        SSL2_VERSION,
        SSL3_VERSION,
        TLS1_VERSION,
        TLS1_1_VERSION,
        TLS1_2_VERSION,
        TLS1_3_VERSION
    };

    // Rest of the function remains structurally the same, just changing result access
    for (size_t i = 0; i < sizeof(protocols)/sizeof(protocols[0]); i++) {
        ctx = SSL_CTX_new(SSLv23_method());
        if (!ctx) continue;

        SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 |
        SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3);

        SSL_CTX_clear_options(ctx,
                              (protocols[i] == SSL2_VERSION) ? SSL_OP_NO_SSLv2 :
                              (protocols[i] == SSL3_VERSION) ? SSL_OP_NO_SSLv3 :
                              (protocols[i] == TLS1_VERSION) ? SSL_OP_NO_TLSv1 :
                              (protocols[i] == TLS1_1_VERSION) ? SSL_OP_NO_TLSv1_1 :
                              (protocols[i] == TLS1_2_VERSION) ? SSL_OP_NO_TLSv1_2 :
                              SSL_OP_NO_TLSv1_3);

        bio = BIO_new_ssl_connect(ctx);
        if (!bio) {
            SSL_CTX_free(ctx);
            continue;
        }

        BIO_set_conn_hostname(bio, host);
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%d", port);
        BIO_set_conn_port(bio, port_str);
        if (time(NULL) - start_time > TIMEOUT_SEC) {
            result->error = "Connection timeout";
            break;
        }

        if (BIO_do_connect(bio) <= 0) {
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            continue;
        }

        BIO_get_ssl(bio, &ssl);
        if (ssl) {
                if (SSL_do_handshake(ssl) <= 0) {
                    fprintf(stderr, "Handshake failed for %s\n", host);
                    BIO_free_all(bio);
                    SSL_CTX_free(ctx);
                    continue;
                }
                   STACK_OF(SSL_CIPHER) *ciphers = SSL_get1_supported_ciphers(ssl);
                result->ciphers = ciphers;
                result->cert = SSL_get_peer_certificate(ssl);


            switch (protocols[i]) {
                case SSL2_VERSION: result->protocol_support.sslv2 = 1; break;
                case SSL3_VERSION: result->protocol_support.sslv3 = 1; break;
                case TLS1_VERSION: result->protocol_support.tlsv1 = 1; break;
                case TLS1_1_VERSION: result->protocol_support.tlsv1_1 = 1; break;
                case TLS1_2_VERSION: result->protocol_support.tlsv1_2 = 1; break;
                case TLS1_3_VERSION: result->protocol_support.tlsv1_3 = 1; break;
            }

            result->ssl = ssl;
            break;
        }

        BIO_free_all(bio);
        SSL_CTX_free(ctx);
    }
}
