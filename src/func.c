#define _POSIX_C_SOURCE 200809L //for strdup
#include "inc/func.h"
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#define PREALLOC_CIPHERS 16
#define MAX_CIPHERS_TO_TEST 32
static pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
static SSL_CTX* tls_ctx_cache[4] = {NULL};
static void init_ctx_cache() {
    if (!tls_ctx_cache[0]) {
        tls_ctx_cache[0] = SSL_CTX_new(TLS_method());
        SSL_CTX_set_min_proto_version(tls_ctx_cache[0], TLS1_VERSION);
        SSL_CTX_set_max_proto_version(tls_ctx_cache[0], TLS1_VERSION);

        tls_ctx_cache[1] = SSL_CTX_new(TLS_method());
        SSL_CTX_set_min_proto_version(tls_ctx_cache[1], TLS1_1_VERSION);
        SSL_CTX_set_max_proto_version(tls_ctx_cache[1], TLS1_1_VERSION);

        tls_ctx_cache[2] = SSL_CTX_new(TLS_method());
        SSL_CTX_set_min_proto_version(tls_ctx_cache[2], TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(tls_ctx_cache[2], TLS1_2_VERSION);

        tls_ctx_cache[3] = SSL_CTX_new(TLS_method());
        SSL_CTX_set_min_proto_version(tls_ctx_cache[3], TLS1_3_VERSION);
        SSL_CTX_set_max_proto_version(tls_ctx_cache[3], TLS1_3_VERSION);
        for (int i = 0; i < 4; i++) {
            SSL_CTX_set_options(tls_ctx_cache[i], SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
            SSL_CTX_set_security_level(tls_ctx_cache[i], 0);
        }
    }
}


static void free_ctx_cache() {
    for (int i = 0; i < 4; i++) {
        if (tls_ctx_cache[i]) {
            SSL_CTX_free(tls_ctx_cache[i]);
            tls_ctx_cache[i] = NULL;
        }
    }
}
 int tcp_connect(const char* host, int port) {
    struct addrinfo hints = {0}, *res = NULL;
    char port_str[16];
    int sockfd = -1;

    snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd < 0) {
        freeaddrinfo(res);
        return -1;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0) {
        close(sockfd);
        freeaddrinfo(res);
        return -1;
}
freeaddrinfo(res);
return sockfd;
}
bool check_heartbleed(const char* host, int port) {
    int sockfd = tcp_connect(host, port);
    if (sockfd < 0) {
        fprintf(stderr, "Connection failed to %s:%d\n", host, port);
        return false;
    }
    const unsigned char hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x31, // Handshake, TLS 1.0, Length 49
        // Handshake Header
        0x01, 0x00, 0x00, 0x2d, // ClientHello
        // Client Version (TLS 1.2) only, there is no support for heartbeat in TLS 1.3
        0x03, 0x03,
        // Random magical hex numbers (32 bit)
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        // Session ID
        0x00, // Zero length

        // Cipher suites (2 suites)
        0x00, 0x04, // Length 4
        0x00, 0x01, // TLS_RSA_WITH_NULL_MD5
        0x00, 0xff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
        0x01, // Length 1
        0x00, // NULL
        0x00, 0x0f, // Extensions length 15
        0x00, 0x0f, // Type: heartbeat(15)
        0x00, 0x01, // Length 1
        0x01 // Mode: Peer_allowed_to_send(1)
    };

    // Heartbeat
    const unsigned char hb[] = {
        0x18, // Heartbeat type
        0x03, 0x03, // TLS 1.2
        0x00, 0x03, // Length 3
        0x01, // Heartbeat_request
        0x40, 0x00 // 16384 bytes
    };

    if (send(sockfd, hello, sizeof(hello), 0) <= 0) {
        close(sockfd);
        return false;
    }
    struct timeval tv = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (send(sockfd, hb, sizeof(hb), 0) <= 0) {
        close(sockfd);
        return false;
    }
    unsigned char response[7];
    ssize_t bytes = recv(sockfd, response, sizeof(response), 0);

    bool vulnerable = false;

    if (bytes > 0) {
        if (response[0] == 0x18) {
            uint16_t length = (response[3] << 8) | response[4];
            if (length > 3) {
                vulnerable = true;
            }
        }
    }

    close(sockfd);
    return vulnerable;
}
void add_cipher(CipherList* list, const char* name, const char* version, int bits, bool is_rsa) {
    if (list->count >= list->capacity) {
        size_t new_cap = (list->capacity == 0) ? 8 : list->capacity * 2;
        CipherInfo* new_buf = realloc(list->ciphers, new_cap * sizeof(CipherInfo));
        if (!new_buf) return;
        list->ciphers = new_buf;
        list->capacity = new_cap;
    }

    list->ciphers[list->count].name = strdup(name);
    list->ciphers[list->count].version = strdup(version);
    list->ciphers[list->count].bits = bits;
    list->ciphers[list->count].is_supported = true;
    list->ciphers[list->count].is_rsa = is_rsa;
    list->count++;
}
static void* test_cipher_thread(void* arg) {
    CipherTask* task = (CipherTask*)arg;

    int sockfd = tcp_connect(task->host, task->port);
    if (sockfd < 0) {
        return NULL;
    }

    SSL* ssl = SSL_new(tls_ctx_cache[task->tls_version_idx]);
    if (!ssl) {
        close(sockfd);
        return NULL;
    }

    if (SSL_set_cipher_list(ssl, task->cipher_name) != 1) {
        SSL_free(ssl);
        close(sockfd);
        return NULL;
    }

    BIO* bio = BIO_new_socket(sockfd, BIO_NOCLOSE);
    SSL_set_bio(ssl, bio, bio);
    SSL_set_tlsext_host_name(ssl, task->host);

    if (SSL_connect(ssl) > 0) {
        const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
        if (cipher) {
            pthread_mutex_lock(&list_mutex);

            bool exists = false;
            for (size_t k = 0; k < task->list->count; k++) {
                if (strcmp(task->list->ciphers[k].name, SSL_CIPHER_get_name(cipher)) == 0) {
                    exists = true;
                    break;
                }
            }

            if (!exists && task->list->count < task->list->capacity) {
                task->list->ciphers[task->list->count].name = strdup(SSL_CIPHER_get_name(cipher));
                task->list->ciphers[task->list->count].bits = SSL_CIPHER_get_bits(cipher, NULL);

                const char* version =
                (task->tls_version_idx == 0) ? "TLSv1" :
                (task->tls_version_idx == 1) ? "TLSv1.1" :
                (task->tls_version_idx == 2) ? "TLSv1.2" : "TLSv1.3";
                task->list->ciphers[task->list->count].version = strdup(version);

                task->list->ciphers[task->list->count].is_supported = true;
                task->list->ciphers[task->list->count].is_rsa =
                (strstr(task->cipher_name, "RSA") != NULL);
                task->list->count++;
            }

            pthread_mutex_unlock(&list_mutex);
        }
        SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    close(sockfd);
    return NULL;
}

CipherList get_supported_ciphers(const char* host, int port) {
    CipherList list = {0};
    list.ciphers = malloc(PREALLOC_CIPHERS * sizeof(CipherInfo));
    if (!list.ciphers) return list;
    list.capacity = PREALLOC_CIPHERS;

    static const char* const ciphers_to_test[MAX_CIPHERS_TO_TEST] = {
        "AES128-SHA", "AES256-SHA",
        "AES128-GCM-SHA256", "AES256-GCM-SHA384",
        "ECDHE-RSA-AES128-SHA", "ECDHE-RSA-AES256-SHA",
        NULL
    };

    init_ctx_cache();

    pthread_t threads[MAX_CIPHERS_TO_TEST * 4];
    CipherTask tasks[MAX_CIPHERS_TO_TEST * 4];
    size_t thread_count = 0;

    for (int i = 0; ciphers_to_test[i] != NULL && i < MAX_CIPHERS_TO_TEST; i++) {
        for (int j = 0; j < 4; j++) {
            if (!tls_ctx_cache[j]) continue;

            tasks[thread_count] = (CipherTask){
                .host = host,
                .port = port,
                .cipher_name = ciphers_to_test[i],
                .tls_version_idx = j,
                .list = &list
            };

            pthread_create(&threads[thread_count], NULL, test_cipher_thread, &tasks[thread_count]);
            thread_count++;
        }
    }

    for (size_t i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    return list;
}
void free_cipher_list(CipherList* list) {
    if (!list) return;
    for (size_t i = 0; i < list->count; i++) {
        free(list->ciphers[i].name);
        free(list->ciphers[i].version);
    }
    free(list->ciphers);
    list->ciphers = NULL;
    list->count = list->capacity = 0;
}

void print_ciphers(const CipherList* list) {
    printf("%-30s | %-8s | %-10s | %s\n", "Cipher", "Bits", "Protocol", "Auth");
    printf("\n");
    for (size_t i = 0; i < list->count; i++) {
        printf("%-30s | %-8d | %-10s | %s\n",
               list->ciphers[i].name,
               list->ciphers[i].bits,
               list->ciphers[i].version,
               list->ciphers[i].is_rsa ? "RSA" : "Other");
    }
}
void init_openssl() {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
     init_ctx_cache();
}
void cleanup_openssl() {
    free_ctx_cache();
    EVP_cleanup();
    ERR_free_strings();
}
//
void print_hex(const unsigned char* data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

void print_cert_info(X509* cert) {
    if (!cert) return;

    printf("Certificate:\n");

    X509_NAME* subject = X509_get_subject_name(cert);
    printf("  Subject: %s\n", X509_NAME_oneline(subject, NULL, 0));

    X509_NAME* issuer = X509_get_issuer_name(cert);
    printf("  Issuer: %s\n", X509_NAME_oneline(issuer, NULL, 0));

    const ASN1_TIME* not_before = X509_get0_notBefore(cert);
    const ASN1_TIME* not_after = X509_get0_notAfter(cert);
    printf("  Valid From: %.*s\n", (int)ASN1_STRING_length(not_before),
           ASN1_STRING_get0_data(not_before));
    printf("  Valid Until: %.*s\n", (int)ASN1_STRING_length(not_after),
           ASN1_STRING_get0_data(not_after));

    const ASN1_INTEGER* serial = X509_get0_serialNumber(cert);
    printf("  Serial: ");
    print_hex(ASN1_STRING_get0_data(serial), (size_t)ASN1_STRING_length(serial));
}

void print_protocol_support(TLSProtocolSupport* support) {
    printf("TLS/SSL support:\n");
    printf("  SSL v2: %s\n", support->sslv2 ? "+" : "-");
    printf("  SSL v3: %s\n", support->sslv3 ? "+" : "-");
    printf("  TLS v1.0: %s\n", support->tlsv1 ? "+" : "-");
    printf("  TLS v1.1: %s\n", support->tlsv1_1 ? "+" : "-");
    printf("  TLS v1.2: %s\n", support->tlsv1_2 ? "+" : "-");
    printf("  TLS v1.3: %s\n", support->tlsv1_3 ? "+" : "-");
}
void check_tls_server(const char* host, size_t port, TLSCheckResult* result) {
    const time_t start_time = time(NULL);
    const size_t TIMEOUT_SEC = 10;
    if (!result) return;

    memset(result, 0, sizeof(TLSCheckResult));
    result->params.host = host;
    result->params.port = port;

    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    BIO* bio = NULL;

    const int protocols[] = {
        SSL2_VERSION,
        SSL3_VERSION,
        TLS1_VERSION,
        TLS1_1_VERSION,
        TLS1_2_VERSION,
        TLS1_3_VERSION
    };

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
        snprintf(port_str, sizeof(port_str), "%zu", port);
        BIO_set_conn_port(bio, port_str);

        if (time(NULL) - start_time > (time_t)TIMEOUT_SEC) {
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
                BIO_free_all(bio);
                SSL_CTX_free(ctx);
                continue;
            }

            result->ciphers = SSL_get1_supported_ciphers(ssl);
            result->cert = SSL_get_peer_certificate(ssl);

            switch (protocols[i]) {
                case SSL2_VERSION: result->protocol_support.sslv2 = true; break;
                case SSL3_VERSION: result->protocol_support.sslv3 = true; break;
                case TLS1_VERSION: result->protocol_support.tlsv1 = true; break;
                case TLS1_1_VERSION: result->protocol_support.tlsv1_1 = true; break;
                case TLS1_2_VERSION: result->protocol_support.tlsv1_2 = true; break;
                case TLS1_3_VERSION: result->protocol_support.tlsv1_3 = true; break;
            }

            result->ssl = ssl;
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            break;
        }

        BIO_free_all(bio);
        SSL_CTX_free(ctx);
    }
}
