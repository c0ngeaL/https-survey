#define _POSIX_C_SOURCE 200112L
#include <check.h>
#include <stdlib.h>
#include <string.h>
#include "inc/common.h"
#include "inc/func.h"
extern bool is_valid_domain(const char *domain);
extern void print_help(const char *program_name);
extern bool is_network_available();
extern int parse_arguments(Options *options, int argc, char **argv);

START_TEST(test_is_valid_domain) {
    ck_assert(is_valid_domain("example.com"));
    ck_assert(is_valid_domain("sub.example.com"));
    ck_assert(!is_valid_domain(""));
    ck_assert(!is_valid_domain("invalid@domain"));
    ck_assert(!is_valid_domain("domain..com"));
}
END_TEST

START_TEST(test_print_help) {
    print_help("test_program");
}
END_TEST

START_TEST(test_is_network_available) {
    bool available = is_network_available();
    ck_assert(available == true || available == false);
}
END_TEST

START_TEST(test_parse_arguments_valid) {
    Options opts = {0};
    char *args[] = {"prog", "example.com"};
    ck_assert_int_eq(parse_arguments(&opts, 2, args), 0);
    ck_assert_int_eq(opts.count, 1);
    ck_assert_str_eq(opts.domains[0], "example.com");
}
END_TEST

START_TEST(test_parse_arguments_invalid) {
    Options opts = {0};
    char *args[] = {"prog", "invalid@"};
    ck_assert_int_ne(parse_arguments(&opts, 2, args), 0);
}
END_TEST

START_TEST(test_parse_arguments_help) {
    Options opts = {0};
    char *args[] = {"prog", "--help"};
    ck_assert_int_eq(parse_arguments(&opts, 2, args), 0);
    ck_assert(opts.show_help);
}
END_TEST

Suite* scanner_suite(void) {
    Suite *s = suite_create("Scanner");
    TCase *tc = tcase_create("Core");

    tcase_add_test(tc, test_is_valid_domain);
    tcase_add_test(tc, test_print_help);
    tcase_add_test(tc, test_is_network_available);
    tcase_add_test(tc, test_parse_arguments_valid);
    tcase_add_test(tc, test_parse_arguments_invalid);
    tcase_add_test(tc, test_parse_arguments_help);

    suite_add_tcase(s, tc);
    return s;
}

int scanner_test_main(void) {
    Suite *s = scanner_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_NORMAL);
    int failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
