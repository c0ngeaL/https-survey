#include <stdio.h>
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
Options parse_arguments(int argc, char **argv) {
    Options options = {0};

    for (int i = 1; i < argc; i++) {

        if (argv[i][0] == '\0') continue;

        switch (argv[i][0]) {
            case '-':

                if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
                    options.show_help = 1;
                    return options;
                } else {
                    fprintf(stderr, "Unknown option, try -help instead '%s'\n", argv[i]);
                    exit(EXIT_FAILURE);
                }
                break;

            default:
                if (options.count >= MAX_DOMAINS) {
                    fprintf(stderr, "Too many domains (max %d)\n", MAX_DOMAINS);
                    exit(EXIT_FAILURE);
                }

                if (strlen(argv[i]) > MAX_DOMAIN_LEN) {
                    fprintf(stderr, "Domain too long (max %d chars)\n", MAX_DOMAIN_LEN);
                    exit(EXIT_FAILURE);
                }

                if (!is_valid_domain(argv[i])) {
                    fprintf(stderr, "Invalid domain '%s'\n", argv[i]);
                    exit(EXIT_FAILURE);
                }

                strncpy(options.domains[options.count], argv[i], MAX_DOMAIN_LEN);
                options.domains[options.count][MAX_DOMAIN_LEN] = '\0';
                options.count++;
                break;
        }
    }
    return options;
}
void print_help() {
    printf("Usage: https-survey <domain>\n");
    printf("Example: https-survey example.com\n");
}
int is_network_available() {
    struct hostent *host = gethostbyname("google.com");
    return host != NULL;
}
int main(int argc, char **argv) {
        Options options = parse_arguments(argc, argv);
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
        TLSCheckResult result = check_tls_server(options.domains[i], 443);
        printf("\nTLS/SSL scan, standby:\n");
         printf("%-30s ║\n", options.domains[i]);
        print_protocol_support(&result.protocol_support);
        printf("\n");
        print_cert_info(result.cert);
        if (result.cert) {
            X509_free(result.cert);
        }
           }
        cleanup_openssl();
        return EXIT_SUCCESS;
}


