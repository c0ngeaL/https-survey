#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <time.h>
#include <stdbool.h>
#include "inc/func.h"
#include "inc/common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_DOMAINS 256
#define MAX_DOMAIN_LEN 253

static FILE *log_file = NULL;

/* Initialize logger with specified filename */
void init_logger(const char* filename)
{
    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }

    if (filename) {
        log_file = fopen(filename, "a");
        if (!log_file) {
            perror("Failed to open log file");
            exit(EXIT_FAILURE);
        }
    }
}
/* Log scan results (same as console output) */
void log_scan_result(const char* domain, const TLSCheckResult* result) {
    if (!log_file || !domain || !result) return;

    time_t now = time(NULL);
    char timestr[20];
    strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(log_file, "[%s] Scan results for %s:\n", timestr, domain);

    if (result->error) {
        fprintf(log_file, "  Error: %s\n", result->error);
        return;
    }

    // Log protocol support
    fprintf(log_file, "  Protocols:\n");
    fprintf(log_file, "    SSLv2: %s\n", result->protocol_support.sslv2 ? "YES" : "NO");
    fprintf(log_file, "    SSLv3: %s\n", result->protocol_support.sslv3 ? "YES" : "NO");
    fprintf(log_file, "    TLSv1.0: %s\n", result->protocol_support.tlsv1 ? "YES" : "NO");
    fprintf(log_file, "    TLSv1.1: %s\n", result->protocol_support.tlsv1_1 ? "YES" : "NO");
    fprintf(log_file, "    TLSv1.2: %s\n", result->protocol_support.tlsv1_2 ? "YES" : "NO");
    fprintf(log_file, "    TLSv1.3: %s\n", result->protocol_support.tlsv1_3 ? "YES" : "NO");

    // Log certificate info
    if (result->cert) {
        fprintf(log_file, "  Certificate:\n");

        X509_NAME* subject = X509_get_subject_name(result->cert);
        char* subject_line = X509_NAME_oneline(subject, NULL, 0);
        if (subject_line) {
            fprintf(log_file, "    Subject: %s\n", subject_line);
            free(subject_line);
        }

        X509_NAME* issuer = X509_get_issuer_name(result->cert);
        char* issuer_line = X509_NAME_oneline(issuer, NULL, 0);
        if (issuer_line) {
            fprintf(log_file, "    Issuer: %s\n", issuer_line);
            free(issuer_line);
        }

        // Log validity period
        BIO *bio = BIO_new(BIO_s_mem());
        if (bio) {
            ASN1_TIME_print(bio, X509_get0_notBefore(result->cert));
            BUF_MEM *bptr;
            BIO_get_mem_ptr(bio, &bptr);
            fprintf(log_file, "    Valid From: %.*s\n", (int)bptr->length, bptr->data);
            BIO_reset(bio);

            ASN1_TIME_print(bio, X509_get0_notAfter(result->cert));
            BIO_get_mem_ptr(bio, &bptr);
            fprintf(log_file, "    Valid Until: %.*s\n", (int)bptr->length, bptr->data);
            BIO_free(bio);
        }

        // Log serial number
        const ASN1_INTEGER* serial = X509_get0_serialNumber(result->cert);
        if (serial) {
            fprintf(log_file, "    Serial: ");
            for (int i = 0; i < ASN1_STRING_length(serial); i++) {
                fprintf(log_file, "%02x", ASN1_STRING_get0_data(serial)[i]);
            }
            fprintf(log_file, "\n");
        }
    }

    // Log ciphers if available
    if (result->ciphers) {
        fprintf(log_file, "  Supported Ciphers:\n");
        fprintf(log_file, "    %-30s | %-8s | %-10s | %s\n", "Cipher", "Bits", "Protocol", "Auth");
        fprintf(log_file, "    %-30s-|-%-8s-|-%-10s-|-%s\n",
                "------------------------------",
                "--------",
                "----------",
                "----");

        CipherList list = get_supported_ciphers(domain, 443);
        for (size_t i = 0; i < list.count; i++) {
            const char* auth_type = list.ciphers[i].is_rsa ? "RSA" :
            (strstr(list.ciphers[i].name, "ECDSA") ? "ECDSA" :
            (strstr(list.ciphers[i].name, "DHE") ? "DH" : "Other"));

            fprintf(log_file, "    %-30s | %-8d | %-10s | %s\n",
                    list.ciphers[i].name,
                    list.ciphers[i].bits,
                    list.ciphers[i].version,
                    auth_type);
        }
        free_cipher_list(&list);
    }

    // Log Heartbleed status
    if (result->cert) {
        bool vulnerable = check_heartbleed(domain, 443);
        fprintf(log_file, "  Heartbleed Vulnerability: %s\n",
                vulnerable ? "VULNERABLE" : "Not vulnerable");
    }

    fflush(log_file); // Ensure data is written to disk
}

/* Validate domain name format */
bool is_valid_domain(const char *domain)
{
    if (!domain || strlen(domain) < 3) {
        return false;
    }

    for (const char *p = domain; *p; p++) {
        if (!((*p >= 'a' && *p <= 'z') ||
            (*p >= 'A' && *p <= 'Z') ||
            (*p >= '0' && *p <= '9') ||
            *p == '-' || *p == '.')) {
            return false;
            }
    }
    return true;
}

/* Print program usage help */
void print_help(const char *program_name)
{
    printf("Usage: %s <domain1> [domain2...]\n", program_name);
    printf("Options:\n");
    printf("  -h, --help    Show this help message\n");
}

/* Check network availability */
bool is_network_available()
{
    struct addrinfo hints = {0}, *result = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    int ret = getaddrinfo("google.com", "80", &hints, &result);
    if (ret != 0) {
        return false;
    }

    freeaddrinfo(result);
    return true;
}

/* Parse command line arguments */
int parse_arguments(Options *options, int argc, char **argv) {
    if (!options) {
        return -1;
    }
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
            fprintf(stderr, "Error: Too many domains (max %d)\n", MAX_DOMAINS);
            return -1;
        }

        if (!is_valid_domain(argv[i])) {
            fprintf(stderr, "Error: Invalid domain '%s'\n", argv[i]);
            return -1;
        }

        // Safe copy with guaranteed null-termination
        strncpy(options->domains[options->count], argv[i], MAX_DOMAIN_LEN - 1);
        options->domains[options->count][MAX_DOMAIN_LEN - 1] = '\0';
        options->count++;
    }

    return 0;
}

/* Process single domain scan */
void process_domain(const char* domain) {
    TLSCheckResult result = {0};
    check_tls_server(domain, 443, &result);

    printf("\nScan results for %s:\n", domain);

    if (result.error) {
        fprintf(stderr, "Error: %s\n", result.error);
        goto cleanup;
    }

    print_protocol_support(&result.protocol_support);

    if (result.ciphers) {
        CipherList list = get_supported_ciphers(domain, 443);
        print_ciphers(&list);
        free_cipher_list(&list);
    }

    if (result.cert) {
        bool vulnerable = check_heartbleed(domain, 443);
        printf("Heartbleed vulnerability: %s\n",
               vulnerable ? "\033[31mVULNERABLE\033[0m" : "\033[32mNot vulnerable\033[0m");
        print_cert_info(result.cert);
    }

    cleanup:
    /* Safe cleanup in correct order */
    if (result.cert) {
        X509_free(result.cert);
        result.cert = NULL;
    }
    if (result.ciphers) {
        sk_SSL_CIPHER_free(result.ciphers);
        result.ciphers = NULL;
    }
    if (result.ssl) {
        SSL_shutdown(result.ssl);
        SSL_free(result.ssl);
        result.ssl = NULL;
    }

    log_scan_result(domain, &result);
}
int main(int argc, char **argv)
{
    Options options;
    init_logger("scan_results.log");

    if (parse_arguments(&options, argc, argv) != 0) {
        return EXIT_FAILURE;
    }

    if (options.show_help || argc < 2) {
        print_help(argv[0]);
        return EXIT_SUCCESS;
    }

    if (!is_network_available()) {
        fprintf(stderr, "Error: No internet connection\n");
        return EXIT_FAILURE;
    }

    init_openssl();
    printf("Starting scan for %d domain(s)...\n", options.count);

    for (int i = 0; i < options.count; i++) {
        process_domain(options.domains[i]);
    }

    cleanup_openssl();

    if (log_file) {
        fclose(log_file);
        log_file = NULL;
    }

    return EXIT_SUCCESS;
}
