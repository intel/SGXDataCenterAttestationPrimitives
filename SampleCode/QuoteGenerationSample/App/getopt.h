#ifndef _GETOPT_H_
#define _GETOPT_H_
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct option {
    const char* name;
    int has_arg;
    int* flag;
    int val;
};

enum {
    no_argument,
    required_argument,
    optional_argument
};

static char* nextchar;
static int optind = 1;
static int opterr = 1;
static int optopt;
static char* optarg;

int getopt_long(int argc, char* const argv[], const char* optstring,
    const struct option* longopts, int* longindex) {
    if (optind >= argc || !argv[optind] || argv[optind][0] != '-' ||
        argv[optind][1] == '\0') {
        return -1;
    }

    if (strcmp(argv[optind], "--") == 0) {
        optind++;
        return -1;
    }

    int opt = -1;
    const char* optchar = NULL;
    optarg = NULL;
    optopt = 0;
    nextchar = NULL;

    if (argv[optind][1] != '-') {
        optchar = strchr(optstring, argv[optind][1]);
        nextchar = argv[optind] + 2;
        opt = argv[optind][1];
        optind++;
    }
    else {
        size_t namelen;
        const struct option* o = longopts;
        const struct option* match = NULL;
        int num_matches = 0;
        optarg = strchr(argv[optind], '=');
        if (optarg != NULL) {
            namelen = optarg - argv[optind] - 2;
            optarg++;
        }
        else {
            namelen = strlen(argv[optind]) - 2;
        }
        for (; o->name != NULL; ++o) {
            if (strncmp(argv[optind] + 2, o->name, namelen) == 0 &&
                namelen == strlen(o->name)) {
                match = o;
                num_matches++;
            }
        }
        if (num_matches == 1) {
            opt = match->val;
            if (longindex != NULL) {
                *longindex = (int)(match - longopts);
            }
            if (match->has_arg != no_argument) {
                if (optarg == NULL) {
                    optarg = argv[optind];
                    optind++;
                }
            }
            else {
                optarg = NULL;
            }
            optind++;
        }
        else {
            opt = '?';
            optopt = 0;
            if (opterr) {
                fprintf(stderr, "Unrecognized option: '%s'\n", argv[optind]);
            }
            optind++;
        }
    }

    if (optchar != NULL && opt != -1) {
        if (optchar[1] == ':') {
            if (optchar[2] == ':') {
                if (*nextchar != '\0') {
                    optarg = nextchar;
                }
                else {
                    optarg = NULL;
                }
            }
            else {
                if (*nextchar != '\0') {
                    optarg = nextchar;
                }
                else {
                    if (optind < argc) {
                        optarg = argv[optind];
                        optind++;
                    }
                    else {
                        optarg = NULL;
                        opt = '?';
                        if (opterr) {
                            fprintf(stderr, "Missing argument for option: '-%c'\n",
                                optchar[0]);
                        }
                    }
                }
            }
        }
        else {
            optarg = NULL;
        }
    }

    return opt;
}

#endif /* _GETOPT_H_ */
