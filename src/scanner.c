#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdbool.h>
#include "inc/func.h"
#include "inc/common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_DOMAINS 256
#define MAX_DOMAIN_LEN 253

bool is_valid_domain(const char *domain) {
    if (!domain || strlen(domain) < 3) return false;
    for (const char *p = domain; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '.')) return false;
    }
    return true;
}

void print_help(const char *program_name) {
    printf("Usage: %s <domain>\n", program_name);
    printf("Example: %s google.com\n", program_name);
}

bool is_network_available() {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int ret = getaddrinfo("google.com", "80", &hints, &result);
    if (ret != 0) return false;
    freeaddrinfo(result);
    return true;
}

int parse_arguments(Options *options, int argc, char **argv) {
    if (!options) return -1;
    memset(options, 0, sizeof(Options));

    static struct option long_options[] = {
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                options->show_help = true;
                return 0;
            default:
                return -1;
        }
    }

    for (int i = optind; i < argc; i++) {
        if (options->count >= MAX_DOMAINS) {
            fprintf(stderr, "Too many domains (max %d)\n", MAX_DOMAINS);
            return -1;
        }
        if (!is_valid_domain(argv[i])) {
            fprintf(stderr, "Invalid domain '%s'\n", argv[i]);
            return -1;
        }
        strncpy(options->domains[options->count], argv[i], MAX_DOMAIN_LEN);
        options->count++;
    }
    return 0;
}

int main(int argc, char **argv) {
    Options options;
    if (parse_arguments(&options, argc, argv) != 0) return EXIT_FAILURE;
    if (options.show_help || argc < 2) {
        print_help(argv[0]);
        return EXIT_SUCCESS;
    }
    if (!is_network_available()) {
        fprintf(stderr, "No internet connection\n");
        return EXIT_FAILURE;
    }

    init_openssl();

    for (int i = 0; i < options.count; i++) {
        TLSCheckResult result;
        check_tls_server(options.domains[i], 443, &result);

        printf("\nTLS scanning for: %s , standby\n", options.domains[i]);
        if (result.error) {
            fprintf(stderr, "Error: %s\n", result.error);
            continue;
        }

        print_protocol_support(&result.protocol_support);

        if (result.ciphers) {
            CipherList list = get_supported_ciphers(options.domains[i], 443);
            print_ciphers(&list);
            free_cipher_list(&list);
        }
        if (result.ciphers) sk_SSL_CIPHER_free(result.ciphers);
        if (result.cert) {
            bool vulnerable = check_heartbleed(options.domains[i], 443);
            printf("Heartbleed check: %s\n",
                   vulnerable ? "\033[31mVULNERABLE!\033[0m" : "\033[32mNot vulnerable!\033[0m");

            print_cert_info(result.cert);
            X509_free(result.cert);
            result.cert = NULL; //no double memory free
        }
        if (result.ssl) SSL_free(result.ssl);
    }
    cleanup_openssl();
    return EXIT_SUCCESS;
}
