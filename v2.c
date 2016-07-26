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

/* C */
#include <assert.h>
#include <stdint.h>
#include <string.h>

/* macaroons */
#include "v2.h"
#include "varint.h"

#define TYPE_LOCATION 1
#define TYPE_IDENTIFIER 2
#define TYPE_VID 4
#define TYPE_SIGNATURE 6
#define EOS 0

struct field
{
    uint8_t type;
    struct slice data;
};

size_t
required_field_size(const struct slice* f)
{
    return 1 + varint_length(f->size) + f->size;
}

size_t
optional_field_size(const struct slice* f)
{
    return f->size ? required_field_size(f) : 0;
}

size_t
macaroon_serialize_size_hint_v2(const struct macaroon* M)
{
    size_t sz = 4 /* 1 for version, 3 for 3 EOS markers */
              + optional_field_size(&M->location)
              + required_field_size(&M->identifier)
              + required_field_size(&M->signature);

    for (size_t i = 0; i < M->num_caveats; ++i)
    {
        sz += optional_field_size(&M->caveats[i].cl);
        sz += required_field_size(&M->caveats[i].cid);
        sz += optional_field_size(&M->caveats[i].vid);
        sz += 1 /* EOS */;
    }

    return sz;
}

int
emit_required_field(uint8_t type, const struct slice* f,
                    unsigned char** ptr,
                    unsigned char* const end)
{
    const size_t sz = 1 + varint_length(f->size) + f->size;
    if (*ptr + sz > end) return -1;
    **ptr = type;
    ++*ptr;
    *ptr = packvarint(f->size, *ptr);
    memmove(*ptr, f->data, f->size);
    *ptr += f->size;
    return 0;
}

int
emit_optional_field(uint8_t type, const struct slice* f,
                    unsigned char** ptr,
                    unsigned char* const end)
{
    return f->size ? emit_required_field(type, f, ptr, end) : 0;
}

int
emit_eos(unsigned char** ptr, unsigned char* const end)
{
    if (*ptr >= end) return -1;
    **ptr = EOS;
    ++*ptr;
    return 0;
}

size_t
macaroon_serialize_v2(const struct macaroon* M,
                      unsigned char* data, size_t data_sz,
                      enum macaroon_returncode* err)
{
    unsigned char* ptr = data;
    unsigned char* const end = ptr + data_sz;
    if (ptr >= end) goto emit_buf_too_small;
    *ptr = 2;
    ++ptr;
    if (emit_optional_field(TYPE_LOCATION, &M->location, &ptr, end) < 0) goto emit_buf_too_small;
    if (emit_required_field(TYPE_IDENTIFIER, &M->identifier, &ptr, end) < 0) goto emit_buf_too_small;
    if (emit_eos(&ptr, end) < 0) goto emit_buf_too_small;

    for (size_t i = 0; i < M->num_caveats; ++i)
    {
        const struct caveat* C = &M->caveats[i];
        if (emit_optional_field(TYPE_LOCATION, &C->cl, &ptr, end) < 0) goto emit_buf_too_small;
        if (emit_required_field(TYPE_IDENTIFIER, &C->cid, &ptr, end) < 0) goto emit_buf_too_small;
        if (emit_optional_field(TYPE_VID, &C->vid, &ptr, end) < 0) goto emit_buf_too_small;
        if (emit_eos(&ptr, end) < 0) goto emit_buf_too_small;
    }

    if (emit_eos(&ptr, end) < 0) goto emit_buf_too_small;
    if (emit_eos(&ptr, end) < 0) goto emit_buf_too_small;
    if (emit_required_field(TYPE_SIGNATURE, &M->signature, &ptr, end) < 0) goto emit_buf_too_small;
    return ptr - data;

emit_buf_too_small:
    *err = MACAROON_BUF_TOO_SMALL;
    return 0;
}

int
parse_field(const unsigned char** _data,
            const unsigned char* const end,
            struct field* parsed)
{
    const unsigned char* data = *_data;
    if (data >= end) return -1;
    uint64_t field = 0;
    uint64_t length = 0;
    data = unpackvarint(data, end, &field);
    if (!data) return -1;
    data = unpackvarint(data, end, &length);
    if (!data) return -1;
    if ((field & 0xffU) != field) return -1;
    if (data + length > end) return -1;
    parsed->type = field & 0xffU;
    parsed->data.data = data;
    parsed->data.size = length;
    data += length;
    assert(data <= end);
    *_data = data;
    return 0;
}

int
parse_optional_field(const unsigned char** data,
                     const unsigned char* const end,
                     uint8_t type,
                     struct field* parsed)
{
    assert((type & 0x7fU) == type);
    if (*data >= end) return -1;

    if (*data == end || (*data < end && **data != type))
    {
        parsed->type = type;
        parsed->data.data = NULL;
        parsed->data.size = 0;
        return 0;
    }

    int ret = parse_field(data, end, parsed);
    assert(ret != 0 || parsed->type == type);
    return ret;
}

int
parse_required_field(const unsigned char** data,
                     const unsigned char* const end,
                     uint8_t type,
                     struct field* parsed)
{
    assert((type & 0x7fU) == type);
    if (*data >= end) return -1;

    if (*data == end || (*data < end && **data != type))
    {
        return -1;
    }

    int ret = parse_field(data, end, parsed);
    assert(ret != 0 || parsed->type == type);
    return ret;
}

int
parse_eos(const unsigned char** data, const unsigned char* const end)
{
    int ret = (*data >= end || **data != EOS) ?  -1 : 0;
    ++*data;
    return ret;
}

struct macaroon*
macaroon_deserialize_v2(const unsigned char* data, size_t data_sz,
                        enum macaroon_returncode* err)
{
    const unsigned char* const end = data + data_sz;

    if (data >= end || *data != 2)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    ++data;
    struct caveat* caveats = malloc(sizeof(struct caveat) * 4);
    size_t caveats_cap = 4;
    size_t caveats_sz = 0;

    struct field location;
    struct field identifier;
    if (parse_optional_field(&data, end, TYPE_LOCATION, &location) < 0) goto parse_invalid;
    if (parse_required_field(&data, end, TYPE_IDENTIFIER, &identifier) < 0) goto parse_invalid;
    if (parse_eos(&data, end) < 0) goto parse_invalid;
    size_t body_sz = location.data.size + identifier.data.size;

    while (data < end && *data != EOS)
    {
        struct field cl;
        struct field cid;
        struct field vid;

        if (parse_optional_field(&data, end, TYPE_LOCATION, &cl) < 0) goto parse_invalid;
        if (parse_required_field(&data, end, TYPE_IDENTIFIER, &cid) < 0) goto parse_invalid;
        if (parse_optional_field(&data, end, TYPE_VID, &vid) < 0) goto parse_invalid;
        if (parse_eos(&data, end) < 0) goto parse_invalid;

        if (caveats_sz == caveats_cap)
        {
            caveats_cap *= 2;
            struct caveat* tmp = realloc(caveats, sizeof(struct caveat) * caveats_cap);
            if (!tmp) goto parse_invalid;
            caveats = tmp;
        }

        caveats[caveats_sz].cid = cid.data;
        caveats[caveats_sz].vid = vid.data;
        caveats[caveats_sz].cl = cl.data;
        ++caveats_sz;
        body_sz += cid.data.size + vid.data.size + cl.data.size;
    }

    if (parse_eos(&data, end) < 0) goto parse_invalid;
    if (parse_eos(&data, end) < 0) goto parse_invalid;
    struct field signature;
    if (parse_required_field(&data, end, TYPE_SIGNATURE, &signature) < 0) goto parse_invalid;
    body_sz += signature.data.size;

    unsigned char* ptr = NULL;
    struct macaroon* M = macaroon_malloc(caveats_sz, body_sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        goto parse_error;
    }

    ptr = copy_slice(&location.data, &M->location, ptr);
    ptr = copy_slice(&identifier.data, &M->identifier, ptr);
    ptr = copy_slice(&signature.data, &M->signature, ptr);
    M->num_caveats = caveats_sz;

    for (size_t i = 0; i < caveats_sz; ++i)
    {
        ptr = copy_slice(&caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_slice(&caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_slice(&caveats[i].cl, &M->caveats[i].cl, ptr);
    }

    free(caveats);
    return M;

parse_invalid:
    *err = MACAROON_INVALID;
parse_error:
    if (caveats)
    {
        free(caveats);
    }

    return NULL;
}
