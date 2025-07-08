#ifndef COMMON_H
#define COMMON_H

#define MAX_DOMAINS 256
#define MAX_DOMAIN_LEN 253

typedef struct {
    char domains[MAX_DOMAINS][MAX_DOMAIN_LEN + 1];
    int count;
    int show_help;
} Options;

#endif
