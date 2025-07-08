#define _POSIX_C_SOURCE 200112L
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "func.h"
#include "src/common.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
extern int is_valid_domain(const char *domain);
extern void print_help(const char *program_name);
extern int is_network_available();
extern int parse_arguments(Options *options, int argc, char **argv);
extern int is_valid_domain(const char *domain);
extern void print_help(const char *program_name);
extern int is_network_available();
extern int parse_arguments(Options *options, int argc, char **argv);

START_TEST(test_is_valid_domain) {
    ck_assert_int_eq(is_valid_domain("google.com"), 1);
    ck_assert_int_eq(is_valid_domain("sub.domain.example.org"), 1);
    ck_assert_int_eq(is_valid_domain("123.com"), 1);
    ck_assert_int_eq(is_valid_domain("a-b.com"), 1);
    ck_assert_int_eq(is_valid_domain(""), 0);
    ck_assert_int_eq(is_valid_domain("a"), 0);
    ck_assert_int_eq(is_valid_domain("invalid@domain.com"), 0);
    ck_assert_int_eq(is_valid_domain("domain..com"), 0);
    ck_assert_int_eq(is_valid_domain(".domain.com"), 0);
    ck_assert_int_eq(is_valid_domain("domain.com."), 0);
}
END_TEST
START_TEST(test_parse_arguments) {
    Options options;
    char *argv[] = {"https-survey", "google.com", "example.com"};
    int argc = 3;

    ck_assert_int_eq(parse_arguments(&options, argc, argv), 0);
    ck_assert_int_eq(options.count, 2);
    ck_assert_str_eq(options.domains[0], "google.com");
    ck_assert_str_eq(options.domains[1], "example.com");
    char *argv_help[] = {"https-survey", "--help"};
    ck_assert_int_eq(parse_arguments(&options, 2, argv_help), 0);
    ck_assert_int_eq(options.show_help, 1);
    char *argv_invalid[] = {"https-survey", "invalid@domain"};
    ck_assert_int_lt(parse_arguments(&options, 2, argv_invalid), 0);
}
END_TEST

START_TEST(test_print_hex) {
    const unsigned char data[] = {0x01, 0x02, 0xAA, 0xFF};
    print_hex(data, sizeof(data));
    print_hex(NULL, 0);
}
END_TEST
START_TEST(test_init_openssl) {
    init_openssl();
    ck_assert_int_eq(ERR_peek_error(), 0);
    cleanup_openssl();
}
END_TEST

Suite *func_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("HTTPS Survey Tests");
    tc_core = tcase_create("Core Functions");

    tcase_add_test(tc_core, test_is_valid_domain);
    tcase_add_test(tc_core, test_parse_arguments);
    tcase_add_test(tc_core, test_print_hex);
    tcase_add_test(tc_core, test_init_openssl);

    suite_add_tcase(s, tc_core);

    return s;
}
