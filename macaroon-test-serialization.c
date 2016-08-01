/* Copyright (c) 2016, Robert Escriva
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
    enum macaroon_format F;
    struct macaroon* M;
};

int
main(int argc, const char* argv[])
{
    char* line = NULL;
    size_t line_sz = 0;
    struct parsed_macaroon* macaroons = NULL;
    size_t macaroons_sz = 0;
    size_t i;
    size_t j;

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
            return EXIT_FAILURE;
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
            return EXIT_FAILURE;
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
            format = MACAROON_V2J;
        }
        else
        {
            fprintf(stderr, "version %s not supported\n", line);
            return EXIT_FAILURE;
        }

        size_t buf_sz = strlen(space + 1);
        unsigned char* buf = malloc(buf_sz);

        if (!buf)
        {
            return EXIT_FAILURE;
        }

        int rc = b64_pton(space + 1, buf, buf_sz);

        if (rc < 0)
        {
            fprintf(stderr, "could not unwrap serialized macaroon\n");
            return EXIT_FAILURE;
        }

        enum macaroon_returncode err;
        struct macaroon* M = macaroon_deserialize(buf, rc, &err);

        if (!M)
        {
            fprintf(stderr, "could not deserialize macaroon: %s\n", macaroon_error(err));
            return EXIT_FAILURE;
        }

        ++macaroons_sz;
        macaroons = realloc(macaroons, macaroons_sz * sizeof(struct parsed_macaroon));

        if (!macaroons)
        {
            return EXIT_FAILURE;
        }

        macaroons[macaroons_sz - 1].F = format;
        macaroons[macaroons_sz - 1].M = M;
    }

    int ret = EXIT_SUCCESS;

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
    }

    (void) argc;
    (void) argv;
    return ret;
}
