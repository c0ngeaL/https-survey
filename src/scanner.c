#define _POSIX_C_SOURCE 200112L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "func.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <netdb.h>

#define MAX_DOMAINS 256
#define MAX_DOMAIN_LEN 253

typedef struct {
    char domains[MAX_DOMAINS][MAX_DOMAIN_LEN + 1];
    int count;
    int show_help;
} Options;

int is_valid_domain(const char *domain);
void print_help(const char *program_name);
int is_network_available();

int is_valid_domain(const char *domain) {
    if (!domain || strlen(domain) < 3) return 0;
    for (const char *p = domain; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '.')) {
            return 0;
            }
    }
    return 1;
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
                options->show_help = 1;
                return 0;
            case '?':
                return -1;
            default:
                fprintf(stderr, "Unexpected error in option processing\n");
                return -1;
        }
    }

    for (int i = optind; i < argc; i++) {
        if (argv[i][0] == '\0') continue;

        if (options->count >= MAX_DOMAINS) {
            fprintf(stderr, "Too many domains (max %d)\n", MAX_DOMAINS);
            return -1;
        }

        if (strlen(argv[i]) > MAX_DOMAIN_LEN) {
            fprintf(stderr, "Domain too long (max %d chars)\n", MAX_DOMAIN_LEN);
            return -1;
        }

        if (!is_valid_domain(argv[i])) {
            fprintf(stderr, "Invalid domain '%s'\n", argv[i]);
            return -1;
        }

        strncpy(options->domains[options->count], argv[i], MAX_DOMAIN_LEN);
        options->domains[options->count][MAX_DOMAIN_LEN] = '\0';
        options->count++;
    }

    return 0;
}
void print_help(const char *program_name) {
    printf("Usage: %s <domain>\n", program_name);
    printf("Example: %s google.com\n", program_name);
}

int is_network_available() {
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    int ret = getaddrinfo("google.com", "80", &hints, &result);
    if (ret != 0) {
        return 0;
        // No connection
    }
    freeaddrinfo(result);
    return 1; // connection active
}

int main(int argc, char **argv) {
    Options options;
    int ret_code;

    if ((ret_code = parse_arguments(&options, argc, argv)) != 0) {
        return ret_code < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
    }

    if (options.show_help || argc < 2) {
        print_help(argv[0]);
        return EXIT_SUCCESS;
    }

    if (!is_network_available()) {
        fprintf(stderr, "No internet connection.\n");
        return EXIT_FAILURE;
    }

    init_openssl();

    for (int i = 0; i < options.count; i++) {
        TLSCheckResult result;
        check_tls_server(options.domains[i], 443, &result);

        printf("\nTLS/SSL scan, standby:\n");
        printf("%-30s\n", options.domains[i]);
        print_protocol_support(&result.protocol_support);
        print_ciphers_from_stack(result.ciphers);

        if (result.cert) {
            X509_free(result.cert);
        }
        if (result.ciphers) {
            sk_SSL_CIPHER_free(result.ciphers);
        }
    }

    cleanup_openssl();
    return EXIT_SUCCESS;
}
