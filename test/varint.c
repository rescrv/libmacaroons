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

/* need to rely upon assert always asserting */
#ifdef NDEBUG
#undef NDEBUG
#endif

/* C */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* macaroons */
#include "varint.h"

void
varint_verify(uint64_t value, const char* representation)
{
    const unsigned sz = strlen(representation);
    assert(sz % 2 == 0);
    unsigned char buf[VARINT_MAX_SIZE];
    uint64_t eulav;
    unsigned int i;
    assert(packvarint(value, buf) == buf + sz / 2);
    assert(unpackvarint(buf, buf + VARINT_MAX_SIZE, &eulav) == buf + sz / 2);
    assert(value == eulav);

    for (i = 0; i < sz / 2; ++i)
    {
        char hex[3];
        snprintf(hex, 3, "%02x", buf[i] & 0xff);
        assert(hex[0] == representation[2 * i]);
        assert(hex[1] == representation[2 * i + 1]);
    }
}

int
main(int argc, const char* argv[])
{
    (void)argc;
    (void)argv;
    varint_verify(0ULL, "00");
    varint_verify(5ULL, "05");
    varint_verify(127ULL, "7f");
    varint_verify(128ULL, "8001");
    varint_verify(16383ULL, "ff7f");
    varint_verify(16384ULL, "808001");
    varint_verify(16385ULL, "818001");
    varint_verify(16386ULL, "828001");
    varint_verify(16387ULL, "838001");
    varint_verify(16388ULL, "848001");
    varint_verify(3735928559ULL, "effdb6f50d");
    varint_verify(18446744073709551615ULL, "ffffffffffffffffff01");
}
