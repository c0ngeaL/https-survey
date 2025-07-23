#define _POSIX_C_SOURCE 200809L // for strdup
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

/* Initialize SSL context cache for different TLS versions */
static pthread_mutex_t ctx_mutex = PTHREAD_MUTEX_INITIALIZER;

static void init_ctx_cache() {
    pthread_mutex_lock(&ctx_mutex);
    if (!tls_ctx_cache[0]) {
        // Create contexts for all supported TLS versions
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

        // Configure common options for all contexts
        for (int i = 0; i < 4; i++) {
            if (tls_ctx_cache[i]) {
                SSL_CTX_set_options(tls_ctx_cache[i], SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
                SSL_CTX_set_security_level(tls_ctx_cache[i], 0);
            }
        }
    }
    pthread_mutex_unlock(&ctx_mutex);
}
/* Clean up SSL context cache */
static void free_ctx_cache()
{
    for (int i = 0; i < 4; i++) {
        if (tls_ctx_cache[i]) {
            SSL_CTX_free(tls_ctx_cache[i]);
            tls_ctx_cache[i] = NULL;
        }
    }
}

/* Establish TCP connection to host:port */
int tcp_connect(const char* host, int port)
{
    struct addrinfo hints = {0}, *res = NULL;
    char port_str[16];
    int sockfd = -1;

    snprintf(port_str, sizeof(port_str), "%d", port);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        return -1;
    }

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

/* Check for Heartbleed vulnerability */
bool check_heartbleed(const char* host, int port)
{
    int sockfd = tcp_connect(host, port);
    if (sockfd < 0) {
        fprintf(stderr, "Connection failed to %s:%d\n", host, port);
        return false;
    }

    // Prepare TLS hello message
    const unsigned char hello[] = {
        // TLS handshake header
        0x16, 0x03, 0x01, 0x00, 0x31,
        // Client hello
        0x01, 0x00, 0x00, 0x2d, 0x03, 0x03,
        // Random bytes
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
        // Session ID and cipher suites
        0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0xff, 0x01,
        0x00, 0x00, 0x0f, 0x00, 0x0f, 0x00, 0x01, 0x01
    };

    // Heartbeat request
    const unsigned char hb[] = {
        0x18, 0x03, 0x03, 0x00, 0x03,
        0x01, 0x40, 0x00
    };

    // Send hello message
    if (send(sockfd, hello, sizeof(hello), 0) <= 0) {
        close(sockfd);
        return false;
    }

    // Set receive timeout
    struct timeval tv = {1, 0};
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    // Send heartbeat request
    if (send(sockfd, hb, sizeof(hb), 0) <= 0) {
        close(sockfd);
        return false;
    }

    // Check response
    unsigned char response[7];
    ssize_t bytes = recv(sockfd, response, sizeof(response), 0);
    bool vulnerable = false;

    if (bytes > 0 && response[0] == 0x18) {
        uint16_t length = (response[3] << 8) | response[4];
        vulnerable = (length > 3);
    }

    close(sockfd);
    return vulnerable;
}


/* Thread function for testing cipher support */
static void* test_cipher_thread(void* arg)
{
    CipherTask* task = (CipherTask*)arg;
    if (!task || !task->host || !task->cipher_name || !task->list) {
        return NULL;
    }

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

            // Check if cipher already exists in list
            bool exists = false;
            for (size_t k = 0; k < task->list->count; k++) {
                if (strcmp(task->list->ciphers[k].name, SSL_CIPHER_get_name(cipher)) == 0) {
                    exists = true;
                    break;
                }
            }

            // Add new cipher if not exists and there's space
            if (!exists && task->list->count < task->list->capacity) {
                char* name = strdup(SSL_CIPHER_get_name(cipher));
                char* version = NULL;

                // Determine TLS version string
                switch (task->tls_version_idx) {
                    case 0: version = strdup("TLSv1"); break;
                    case 1: version = strdup("TLSv1.1"); break;
                    case 2: version = strdup("TLSv1.2"); break;
                    case 3: version = strdup("TLSv1.3"); break;
                    default: version = strdup("Unknown"); break;
                }

                if (name && version) {
                    task->list->ciphers[task->list->count].name = name;
                    task->list->ciphers[task->list->count].version = version;
                    task->list->ciphers[task->list->count].bits = SSL_CIPHER_get_bits(cipher, NULL);
                    task->list->ciphers[task->list->count].is_rsa = (strstr(task->cipher_name, "RSA") != NULL);
                    task->list->count++;
                } else {
                    free(name);
                    free(version);
                }
            }
            pthread_mutex_unlock(&list_mutex);
        }
        SSL_shutdown(ssl);
    }

    SSL_free(ssl);
    close(sockfd);
    return NULL;
}

/* Get list of supported ciphers for host:port */
CipherList get_supported_ciphers(const char* host, int port) {
    CipherList list = {0};
    list.ciphers = malloc(PREALLOC_CIPHERS * sizeof(CipherInfo));
    if (!list.ciphers) return list;
    list.capacity = PREALLOC_CIPHERS;
    static const char* const ciphers_to_test[MAX_CIPHERS_TO_TEST] = {
        // Modern TLS 1.3 ciphers
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_GCM_SHA256",


        "ECDHE-ECDSA-AES256-GCM-SHA384",
        "ECDHE-RSA-AES256-GCM-SHA384",
        "ECDHE-RSA-CHACHA20-POLY1305",
        "ECDHE-ECDSA-AES128-GCM-SHA256",
        "ECDHE-RSA-AES128-SHA256",


        "DHE-RSA-AES256-GCM-SHA384",
        "DHE-RSA-AES128-GCM-SHA256",
        "DHE-RSA-AES256-SHA256",

        "AES256-GCM-SHA384",
        "AES128-GCM-SHA256",
        "AES256-SHA256",
        "AES128-SHA256",
        "AES128-SHA",


        "DES-CBC3-SHA",
        "RC4-SHA",
        "ECDHE-RSA-RC4-SHA",
        NULL
    };

    init_ctx_cache();

    pthread_t threads[MAX_CIPHERS_TO_TEST * 4];
    CipherTask tasks[MAX_CIPHERS_TO_TEST * 4];
    size_t thread_count = 0;

    // Create threads for each cipher and TLS version combination
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

            if (pthread_create(&threads[thread_count], NULL, test_cipher_thread, &tasks[thread_count]) == 0) {
                thread_count++;
            }
        }
    }

    // Wait for all threads to complete
    for (size_t i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    return list;
}

/* Free cipher list and all its resources */
void free_cipher_list(CipherList* list)
{
    if (!list) return;

    if (list->ciphers) {
        for (size_t i = 0; i < list->count; i++) {
            free(list->ciphers[i].name);    // Freed even if NULL
            free(list->ciphers[i].version); // Freed even if NULL
        }
        free(list->ciphers);
    }

    list->ciphers = NULL;
    list->count = 0;
    list->capacity = 0;
}

/* Print cipher list in formatted table */
void print_ciphers(const CipherList* list)
{
    if (!list) return;

    printf("%-30s | %-8s | %-10s | %s\n", "Cipher", "Bits", "Protocol", "Auth");
    printf("------------------------------ | -------- | ---------- | -----\n");

    for (size_t i = 0; i < list->count; i++) {
        printf("%-30s | %-8d | %-10s | %s\n",
               list->ciphers[i].name,
               list->ciphers[i].bits,
               list->ciphers[i].version,
               list->ciphers[i].is_rsa ? "RSA" : "Other");
    }
}

/* Initialize OpenSSL library */
static pthread_once_t openssl_init_once = PTHREAD_ONCE_INIT;

static void openssl_init_internal(void) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    init_ctx_cache();
}

void init_openssl() {
    pthread_once(&openssl_init_once, openssl_init_internal);
}

/* Clean up OpenSSL resources */
void cleanup_openssl()
{
    free_ctx_cache();
    EVP_cleanup();
    ERR_free_strings();
}

/* Print data in hex format */
void print_hex(const unsigned char* data, size_t len)
{
    if (!data) return;

    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

/* Print certificate information */
void print_cert_info(X509* cert) {
    if (!cert) return;

    printf("Certificate:\n");

    // Print subject
    X509_NAME* subject = X509_get_subject_name(cert);
    char* subject_line = X509_NAME_oneline(subject, NULL, 0);
    if (subject_line) {
        printf("  Subject: %s\n", subject_line);
        free(subject_line);
    }

    // Print issuer
    X509_NAME* issuer = X509_get_issuer_name(cert);
    char* issuer_line = X509_NAME_oneline(issuer, NULL, 0);
    if (issuer_line) {
        printf("  Issuer: %s\n", issuer_line);
        free(issuer_line);
    }

    // Print validity period using BIO for safety
    BIO *bio = BIO_new(BIO_s_mem());
    if (bio) {
        ASN1_TIME_print(bio, X509_get0_notBefore(cert));
        BUF_MEM *bptr;
        BIO_get_mem_ptr(bio, &bptr);
        printf("  Valid From: %.*s\n", (int)bptr->length, bptr->data);
        BIO_reset(bio);

        ASN1_TIME_print(bio, X509_get0_notAfter(cert));
        BIO_get_mem_ptr(bio, &bptr);
        printf("  Valid Until: %.*s\n", (int)bptr->length, bptr->data);
        BIO_free(bio);
    }

    // Print serial number
    const ASN1_INTEGER* serial = X509_get0_serialNumber(cert);
    if (serial) {
        printf("  Serial: ");
        print_hex(ASN1_STRING_get0_data(serial), (size_t)ASN1_STRING_length(serial));
    }
}

/* Print supported protocol versions */
void print_protocol_support(TLSProtocolSupport* support)
{
    if (!support) return;

    printf("TLS/SSL support:\n");
    printf("  SSL v2: %s\n", support->sslv2 ? "+" : "-");
    printf("  SSL v3: %s\n", support->sslv3 ? "+" : "-");
    printf("  TLS v1.0: %s\n", support->tlsv1 ? "+" : "-");
    printf("  TLS v1.1: %s\n", support->tlsv1_1 ? "+" : "-");
    printf("  TLS v1.2: %s\n", support->tlsv1_2 ? "+" : "-");
    printf("  TLS v1.3: %s\n", support->tlsv1_3 ? "+" : "-");
}
/* Check TLS server capabilities */
void check_tls_server(const char* host, size_t port, TLSCheckResult* result) {
    if (!host || !result) return;

    const time_t start_time = time(NULL);
    const size_t TIMEOUT_SEC = 10;

    // Initialize result structure
    memset(result, 0, sizeof(TLSCheckResult));
    result->params.host = host;
    result->params.port = port;

    SSL_CTX* ctx = NULL;
    SSL* ssl = NULL;
    BIO* bio = NULL;

    // Supported protocol versions in order of preference
    const struct {
        int version;
        const char *name;
    } protocols[] = {
        {TLS1_3_VERSION, "TLSv1.3"},
        {TLS1_2_VERSION, "TLSv1.2"},
        {TLS1_1_VERSION, "TLSv1.1"},
        {TLS1_VERSION, "TLSv1.0"},
        {0, NULL} // Terminator
    };

    for (int i = 0; protocols[i].name; i++) {
        // Check timeout
        if (time(NULL) - start_time > (time_t)TIMEOUT_SEC) {
            result->error = "Connection timeout";
            break;
        }

        // Create fresh context for each protocol
        ctx = SSL_CTX_new(TLS_method());
        if (!ctx) {
            fprintf(stderr, "Failed to create SSL context for %s\n", protocols[i].name);
            continue;
        }

        // Set EXACTLY this protocol version (no fallback)
        SSL_CTX_set_min_proto_version(ctx, protocols[i].version);
        SSL_CTX_set_max_proto_version(ctx, protocols[i].version);

        // Additional security settings
        SSL_CTX_set_options(ctx, SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);
        SSL_CTX_set_security_level(ctx, 1); // Moderate security level

        bio = BIO_new_ssl_connect(ctx);
        if (!bio) {
            fprintf(stderr, "Failed to create BIO for %s\n", protocols[i].name);
            SSL_CTX_free(ctx);
            continue;
        }

        // Configure connection
        BIO_set_conn_hostname(bio, host);
        char port_str[16];
        snprintf(port_str, sizeof(port_str), "%zu", port);
        BIO_set_conn_port(bio, port_str);

        // Attempt connection
        if (BIO_do_connect(bio) <= 0) {
            unsigned long err = ERR_get_error();
            fprintf(stderr, "Connection failed for %s: ", protocols[i].name);
            ERR_print_errors_fp(stderr);

            // Check for host resolution errors
            if (err && ERR_GET_LIB(err) == ERR_LIB_BIO &&
                ERR_GET_REASON(err) == BIO_RR_CONNECT) {
                result->error = "Host resolution failed (non-existent domain)";
            BIO_free_all(bio);
            SSL_CTX_free(ctx);
            return;
                }

                BIO_free_all(bio);
                SSL_CTX_free(ctx);
                continue;
        }

        // Get SSL object
        if (BIO_get_ssl(bio, &ssl) && ssl) {
            // Perform handshake
            int handshake_result = SSL_do_handshake(ssl);
            if (handshake_result > 0) {
                // Success!
                result->ciphers = SSL_get1_supported_ciphers(ssl);
                result->cert = SSL_get_peer_certificate(ssl);
                result->ssl = ssl;

                // Mark supported protocol
                switch (protocols[i].version) {
                    case TLS1_3_VERSION: result->protocol_support.tlsv1_3 = true; break;
                    case TLS1_2_VERSION: result->protocol_support.tlsv1_2 = true; break;
                    case TLS1_1_VERSION: result->protocol_support.tlsv1_1 = true; break;
                    case TLS1_VERSION: result->protocol_support.tlsv1 = true; break;
                }

                // bio and ctx are now owned by SSL object
                return;
            } else {
                // Check for host resolution errors during handshake
                int ssl_error = SSL_get_error(ssl, handshake_result);
                if (ssl_error == SSL_ERROR_SYSCALL) {
                    result->error = "Connection failed (host unreachable)";
                    BIO_free_all(bio);
                    SSL_CTX_free(ctx);
                    return;
                }
            }
        }

        // Cleanup failed attempt
        BIO_free_all(bio);
        SSL_CTX_free(ctx);
    }

    // If we get here, all attempts failed
    if (!result->error) {
        result->error = "No supported protocol found";
    }
}
