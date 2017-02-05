/* Copyright (c) 2016-2017, Robert Escriva
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright notice,
 *       this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of this project nor the names of its contributors may
 *       be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _WITH_GETLINE

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* C */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* macaroons */
#include "macaroons.h"
#include "base64.h"

struct parsed_macaroon
{
    unsigned char* B;
    struct macaroon* M;
    enum macaroon_format F;
};

int
repeated_serialization_cycle(struct macaroon* M, enum macaroon_format F)
{
    int ret = 0;
    char* buf = NULL;
    size_t buf_sz = 0;
    struct macaroon* N = NULL;
    size_t sz;
    enum macaroon_returncode err;

    buf_sz = macaroon_serialize_size_hint(M, F);
    buf = malloc(buf_sz);
    if (!buf) goto fail;
    sz = macaroon_serialize(M, F, buf, buf_sz, &err);
    if (sz == 0) goto fail;
    N = macaroon_deserialize(buf, sz, &err);
    if (!N) goto fail;
    ret = macaroon_cmp(M, N);
    goto done;

fail:
    ret = -1;

done:
    if (buf) free(buf);
    if (N)
    return ret;
}

int
main(int argc, const char* argv[])
{
    char* line = NULL;
    size_t line_sz = 0;
    struct parsed_macaroon* tmp = NULL;
    struct parsed_macaroon* macaroons = NULL;
    size_t macaroons_sz = 0;
    size_t i;
    size_t j;
    int ret = EXIT_SUCCESS;

    while (1)
    {
        ssize_t amt = getline(&line, &line_sz, stdin);

        if (amt < 0)
        {
            if (feof(stdin) != 0)
            {
                break;
            }

            fprintf(stderr, "could not read from stdin: %s\n", strerror(ferror(stdin)));
            goto fail;
        }

        if (!line || amt == 0 || *line == '\n' || *line == '#')
        {
            continue;
        }

        line[amt - 1] = '\0';
        char* space = strchr(line, ' ');
        char* const end = line + amt - 1;

        if (!space)
        {
            fprintf(stderr, "space missing on line %lu\n", macaroons_sz + 1);
            goto fail;
        }

        assert(space < end);
        *space = '\0';
        enum macaroon_format format;

        if (strcmp(line, "v1") == 0)
        {
            format = MACAROON_V1;
        }
        else if (strcmp(line, "v2") == 0)
        {
            format = MACAROON_V2;
        }
        else if (strcmp(line, "v2j") == 0)
        {
#ifdef MACAROONS_JSON
            format = MACAROON_V2J;
#else
            printf("format v2j not supported\n");
            continue;
#endif
        }
        else
        {
            fprintf(stderr, "version %s not supported\n", line);
            goto fail;
        }

        size_t buf_sz = strlen(space + 1);
        unsigned char* buf = malloc(buf_sz);

        if (!buf)
        {
            goto fail;
        }

        memset(buf, 0, sizeof(buf));
        int rc = b64_pton(space + 1, buf, buf_sz);

        if (rc < 0)
        {
            fprintf(stderr, "could not unwrap serialized macaroon\n");
            goto fail;
        }

        enum macaroon_returncode err;
        struct macaroon* M = macaroon_deserialize(buf, rc, &err);

        if (!M)
        {
            fprintf(stderr, "could not deserialize macaroon: %s\n", macaroon_error(err));
            goto fail;
        }

        ++macaroons_sz;
        tmp = realloc(macaroons, macaroons_sz * sizeof(struct parsed_macaroon));

        if (!tmp)
        {
            goto fail;
        }

        macaroons = tmp;
        macaroons[macaroons_sz - 1].F = format;
        macaroons[macaroons_sz - 1].M = M;
        macaroons[macaroons_sz - 1].B = buf;
    }

    ret = EXIT_SUCCESS;

    for (i = 0; i < macaroons_sz; ++i)
    {
        for (j = i + 1; j < macaroons_sz; ++j)
        {
            if (macaroon_cmp(macaroons[i].M, macaroons[j].M) != 0)
            {
                printf("macaroons %lu and %lu do not match\n", i, j);
                ret = EXIT_FAILURE;
            }
        }

        if (repeated_serialization_cycle(macaroons[i].M, MACAROON_V1) != 0)
        {
            printf("macaroons %lu does not reserialize via V1\n", i);
            ret = EXIT_FAILURE;
        }

        if (repeated_serialization_cycle(macaroons[i].M, MACAROON_V2) != 0)
        {
            printf("macaroons %lu does not reserialize via V2\n", i);
            ret = EXIT_FAILURE;
        }

        if (repeated_serialization_cycle(macaroons[i].M, MACAROON_V2J) != 0)
        {
            printf("macaroons %lu does not reserialize via V2J\n", i);
            ret = EXIT_FAILURE;
        }
    }

    goto exit;

fail:
    ret = EXIT_FAILURE;

exit:
    if (line)
    {
        free(line);
    }

    for (i = 0; i < macaroons_sz; ++i)
    {
        if (macaroons[i].B)
        {
            free(macaroons[i].B);
        }

        if (macaroons[i].M)
        {
            macaroon_destroy(macaroons[i].M);
        }
    }

    if (macaroons)
    {
        free(macaroons);
    }

    (void) argc;
    (void) argv;
    return ret;
}
