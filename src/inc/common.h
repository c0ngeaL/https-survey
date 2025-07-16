#ifndef COMMON_H
#define COMMON_H
#include <stdbool.h>
#define MAX_DOMAINS 256
#define MAX_DOMAIN_LEN 253
typedef struct {
    char domains[MAX_DOMAINS][MAX_DOMAIN_LEN + 1];
    int count;
    int show_help;
} Options;
/* Logger functions */
void init_logger(const char* filename);
void log_message(const char* message);
void update_progress(int current, int total);

/* Domain validation */
bool is_valid_domain(const char *domain);
int parse_arguments(Options *options, int argc, char **argv);
void print_help(const char *program_name);
bool is_network_available();
#endif
