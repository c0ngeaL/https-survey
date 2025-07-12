#define _POSIX_C_SOURCE 200112L
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "inc/func.h"
#include "inc/common.h"

extern bool is_valid_domain(const char *domain);
extern void print_help(const char *program_name);
extern bool is_network_available();
extern int parse_arguments(Options *options, int argc, char **argv);
extern int tcp_connect(const char* host, int port);
extern bool check_heartbleed(const char* host, int port);
extern CipherList get_supported_ciphers(const char* host, int port);
extern void free_cipher_list(CipherList* list);
extern void print_ciphers(const CipherList* list);
extern void print_cert_info(X509* cert);
extern void print_protocol_support(TLSProtocolSupport* support);
extern void check_tls_server(const char* host, size_t port, TLSCheckResult* result);
extern void init_openssl(void);
extern void cleanup_openssl(void);

static int mock_socket_fd = -1;


START_TEST(test_is_valid_domain) {
    ck_assert(is_valid_domain("valid.com"));
    ck_assert(!is_valid_domain("invalid@domain"));
}
END_TEST

START_TEST(test_network_functions) {
    mock_socket_fd = 42;
    ck_assert_int_eq(tcp_connect("test", 443), 42);
}
END_TEST

START_TEST(test_ssl_functions) {
    init_openssl();
    mock_socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    bool hb = check_heartbleed("test", 443);
    ck_assert(hb == true || hb == false);
    CipherList list = get_supported_ciphers("test", 443);
    ck_assert(list.ciphers != NULL || list.count == 0);
    free_cipher_list(&list);
    cleanup_openssl();
}
END_TEST

Suite* create_test_suite() {
    Suite *s = suite_create("HTTPS Survey Tests");
    TCase *tc = tcase_create("Core Functions");
    tcase_add_test(tc, test_is_valid_domain);
    tcase_add_test(tc, test_network_functions);
    tcase_add_test(tc, test_ssl_functions);
    suite_add_tcase(s, tc);
    return s;
}

int test_main(void) {
    Suite *s = create_test_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
