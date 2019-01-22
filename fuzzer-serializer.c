//
// Created by Nicholas Robison on 2019-01-22.
//

/* C */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* macaroons */
#include "macaroons.h"
#include "base64.h"

struct parsed_macaroon {
    unsigned char *B;
    struct macaroon *M;
    enum macaroon_format F;
};

size_t
int2size_t(int val) {
    return (val < 0) ? __SIZE_MAX__ : (size_t)((unsigned) val);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    char *line = (char *)data;
    size_t amt = size;
    struct parsed_macaroon *tmp = NULL;
    struct parsed_macaroon *macaroons = NULL;
    size_t macaroons_sz = 0;
    size_t i;
    size_t j;
    int ret = EXIT_SUCCESS;

    while (1) {
        if (!line || amt == 0 || *line == '\n' || *line == '#') {
            continue;
        }

        line[amt - 1] = '\0';
        char *space = strchr(line, ' ');
        char *const end = line + amt - 1;

        if (!space) {
            fprintf(stderr, "space missing on line %lu\n", macaroons_sz + 1);
            goto fail;
        }

        assert(space < end);
        *space = '\0';
        enum macaroon_format format;

        if (strcmp(line, "v1") == 0) {
            format = MACAROON_V1;
        } else if (strcmp(line, "v2") == 0) {
            format = MACAROON_V2;
        } else if (strcmp(line, "v2j") == 0) {
#ifdef MACAROONS_JSON
            format = MACAROON_V2J;
#else
            printf("format v2j not supported\n");
            continue;
#endif
        } else {
            fprintf(stderr, "version %s not supported\n", line);
            goto fail;
        }

        size_t buf_sz = strlen(space + 1);
        unsigned char *buf = malloc(buf_sz);

        if (!buf) {
            goto fail;
        }

        memset(buf, 0, sizeof(*buf));
        int rc = b64_pton(space + 1, buf, buf_sz);

        if (rc < 0) {
            fprintf(stderr, "could not unwrap serialized macaroon\n");
            goto fail;
        }

        enum macaroon_returncode err;
        struct macaroon *M = macaroon_deserialize(buf, int2size_t(rc), &err);

        if (!M) {
            fprintf(stderr, "could not deserialize macaroon: %s\n", macaroon_error(err));
            goto fail;
        }

        ++macaroons_sz;
        tmp = realloc(macaroons, macaroons_sz * sizeof(struct parsed_macaroon));

        if (!tmp) {
            goto fail;
        }

        macaroons = tmp;
        macaroons[macaroons_sz - 1].F = format;
        macaroons[macaroons_sz - 1].M = M;
        macaroons[macaroons_sz - 1].B = buf;
    }

    ret = EXIT_SUCCESS;

    for (i = 0; i < macaroons_sz; ++i) {
        for (j = i + 1; j < macaroons_sz; ++j) {
            if (macaroon_cmp(macaroons[i].M, macaroons[j].M) != 0) {
                printf("macaroons %lu and %lu do not match\n", i, j);
                ret = EXIT_FAILURE;
            }
        }
    }

    goto exit;

    fail:
    ret = EXIT_FAILURE;

    exit:
    if (line) {
        free(line);
    }

    for (i = 0; i < macaroons_sz; ++i) {
        if (macaroons[i].B) {
            free(macaroons[i].B);
        }

        if (macaroons[i].M) {
            macaroon_destroy(macaroons[i].M);
        }
    }

    if (macaroons) {
        free(macaroons);
    }
    return ret;
}