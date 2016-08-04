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
#include "constants.h"
#include "varint.h"

#define TYPE_LOCATION 1
#define TYPE_IDENTIFIER 2
#define TYPE_VID 4
#define TYPE_SIGNATURE 6
#define EOS 0

#define ENC_STR 1
#define ENC_HEX 2
#define ENC_B64 3

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
    size_t i;
    size_t sz = 4 /* 1 for version, 3 for 3 EOS markers */
              + optional_field_size(&M->location)
              + required_field_size(&M->identifier)
              + required_field_size(&M->signature);

    for (i = 0; i < M->num_caveats; ++i)
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
    size_t i;
    if (ptr >= end) goto emit_buf_too_small;
    *ptr = 2;
    ++ptr;
    if (emit_optional_field(TYPE_LOCATION, &M->location, &ptr, end) < 0) goto emit_buf_too_small;
    if (emit_required_field(TYPE_IDENTIFIER, &M->identifier, &ptr, end) < 0) goto emit_buf_too_small;
    if (emit_eos(&ptr, end) < 0) goto emit_buf_too_small;

    for (i = 0; i < M->num_caveats; ++i)
    {
        const struct caveat* C = &M->caveats[i];
        if (emit_optional_field(TYPE_LOCATION, &C->cl, &ptr, end) < 0) goto emit_buf_too_small;
        if (emit_required_field(TYPE_IDENTIFIER, &C->cid, &ptr, end) < 0) goto emit_buf_too_small;
        if (emit_optional_field(TYPE_VID, &C->vid, &ptr, end) < 0) goto emit_buf_too_small;
        if (emit_eos(&ptr, end) < 0) goto emit_buf_too_small;
    }

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
    size_t i;

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

    for (i = 0; i < caveats_sz; ++i)
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

#define JSON_START "{\"v\":2"
#define JSON_CAVEATS_START ",\"c\":["
#define JSON_CAVEATS_FINISH "],"

#define JSON_MAX_FIELD_SIZE 1

const char*
json_field_type(uint8_t type)
{
    /* If you elongate these strings, update JSON_MAX_FIELD_SIZE */
    switch (type)
    {
        case TYPE_LOCATION:
            return "l";
        case TYPE_IDENTIFIER:
            return "i";
        case TYPE_VID:
            return "v";
        case TYPE_SIGNATURE:
            return "s";
        default:
            return NULL;
    }
}

size_t
json_required_field_size(int encoding, const struct slice* f)
{
    switch (encoding)
    {
        case ENC_STR:
            return 6 + JSON_MAX_FIELD_SIZE + f->size;
        case ENC_HEX:
            return 6 + JSON_MAX_FIELD_SIZE + 2 * f->size;
        case ENC_B64:
            return 6 + JSON_MAX_FIELD_SIZE + (8 * f->size + 7) / 6;
        default:
            abort();
    }
}

size_t
json_optional_field_size(int encoding, const struct slice* f)
{
    return f->size ? json_required_field_size(encoding, f) : 0;
}

size_t
macaroon_serialize_size_hint_v2j(const struct macaroon* M)
{
    size_t i;
    size_t sz = STRLENOF(JSON_START)
              + STRLENOF(JSON_CAVEATS_START)
              + STRLENOF(JSON_CAVEATS_FINISH)
              + 1 /* finishing */
              + json_optional_field_size(ENC_STR, &M->location)
              + json_required_field_size(ENC_STR, &M->identifier)
              + json_required_field_size(ENC_B64, &M->signature);

    for (i = 0; i < M->num_caveats; ++i)
    {
        sz += 3; /* ,{} */
        sz += json_optional_field_size(ENC_STR, &M->caveats[i].cl);
        sz += json_required_field_size(ENC_STR, &M->caveats[i].cid);
        sz += json_optional_field_size(ENC_STR, &M->caveats[i].vid);
    }

    return sz;
}

void
json_emit_char(unsigned char c,
               unsigned char** ptr,
               unsigned char* const end)
{
    assert(*ptr < end);
    **ptr = c;
    ++*ptr;
}

int
json_emit_string(const char* str, size_t str_sz,
                 unsigned char** ptr,
                 unsigned char* const end)
{
    if (*ptr + str_sz + 2 > end) return -1;
    json_emit_char('"', ptr, end);
    memmove(*ptr, str, str_sz);
    *ptr += str_sz;
    json_emit_char('"', ptr, end);
    return 0;
}

int
json_emit_string_b64(const char* str, size_t str_sz,
                     unsigned char** ptr,
                     unsigned char* const end)
{
    const size_t b64_sz = (str_sz * 8 + 7) / 6;
    if (*ptr + b64_sz + 2 > end) return -1;
    json_emit_char('"', ptr, end);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpointer-sign"
    int ret = b64_ntop(str, str_sz, *ptr, end - *ptr);
    if (ret < 0) return -1;
    *ptr += ret;
#pragma GCC diagnostic pop
    json_emit_char('"', ptr, end);
    return 0;
}

int
json_emit_encoded_string(int encoding,
                         const char* str, size_t str_sz,
                         unsigned char** ptr,
                         unsigned char* const end)
{
    switch (encoding)
    {
        case ENC_STR:
            /* XXX check that it is UTF-8 and switch to other case if not */
            /* XXX if the above XXX is addressed, remember to adjust sz hint */
            return json_emit_string(str, str_sz, ptr, end);
        case ENC_B64:
            return json_emit_string_b64(str, str_sz, ptr, end);
        case ENC_HEX:
        default:
            return -1;
    }
}

int
json_emit_required_field(int comma, int encoding, uint8_t _type,
                         const struct slice* f,
                         unsigned char** ptr,
                         unsigned char* const end)
{
    const char* type = json_field_type(_type);
    assert(type);
    const size_t type_sz = strlen(type);
    const size_t sz = 6/*quote field + quote value + colon + comma */
                    + type_sz + f->size;
    if (*ptr + sz > end) return -1;
    if (comma) json_emit_char(',', ptr, end);
    if (json_emit_string(type, type_sz, ptr, end) < 0) return -1;
    json_emit_char(':', ptr, end);
    if (json_emit_encoded_string(encoding, (const char*)f->data, f->size, ptr, end) < 0) return -1;
    assert(*ptr <= end);
    return 0;
}

int
json_emit_optional_field(int comma, int encoding, uint8_t type,
                         const struct slice* f,
                         unsigned char** ptr,
                         unsigned char* const end)
{
    return f->size ? json_emit_required_field(comma, encoding, type, f, ptr, end) : 0;
}

int
json_emit_start(unsigned char** ptr,
                unsigned char* const end)
{
    const size_t sz = STRLENOF(JSON_START);
    if (*ptr + sz > end) return -1;
    memmove(*ptr, JSON_START, sz);
    *ptr += sz;
    return 0;
}

int
json_emit_finish(unsigned char** ptr,
                 unsigned char* const end)
{
    if (*ptr >= end) return -1;
    json_emit_char('}', ptr, end);
    return 0;
}

int
json_emit_caveats_start(unsigned char** ptr,
                        unsigned char* const end)
{
    const size_t sz = STRLENOF(JSON_CAVEATS_START);
    if (*ptr + sz > end) return -1;
    memmove(*ptr, JSON_CAVEATS_START, sz);
    *ptr += sz;
    return 0;
}

int
json_emit_caveats_finish(unsigned char** ptr,
                         unsigned char* const end)
{
    const size_t sz = STRLENOF(JSON_CAVEATS_FINISH);
    if (*ptr + sz > end) return -1;
    memmove(*ptr, JSON_CAVEATS_FINISH, sz);
    *ptr += sz;
    return 0;
}

size_t
macaroon_serialize_v2j(const struct macaroon* M,
                       unsigned char* data, size_t data_sz,
                       enum macaroon_returncode* err)
{
    unsigned char* ptr = data;
    unsigned char* const end = ptr + data_sz;
    size_t i;
    if (ptr >= end) goto json_emit_buf_too_small;
    if (json_emit_start(&ptr, end) < 0) goto json_emit_buf_too_small;
    if (json_emit_optional_field(1, ENC_STR, TYPE_LOCATION, &M->location, &ptr, end) < 0) goto json_emit_buf_too_small;
    if (json_emit_required_field(1, ENC_STR, TYPE_IDENTIFIER, &M->identifier, &ptr, end) < 0) goto json_emit_buf_too_small;
    if (json_emit_caveats_start(&ptr, end) < 0) goto json_emit_buf_too_small;

    for (i = 0; i < M->num_caveats; ++i)
    {
        const struct caveat* C = &M->caveats[i];
        if (ptr + 3 >= end) goto json_emit_buf_too_small;
        if (i > 0) json_emit_char(',', &ptr, end);
        json_emit_char('{', &ptr, end);
        if (json_emit_required_field(0, ENC_STR, TYPE_IDENTIFIER, &C->cid, &ptr, end) < 0) goto json_emit_buf_too_small;
        if (json_emit_optional_field(1, ENC_STR, TYPE_LOCATION, &C->cl, &ptr, end) < 0) goto json_emit_buf_too_small;
        if (json_emit_optional_field(1, ENC_STR, TYPE_VID, &C->vid, &ptr, end) < 0) goto json_emit_buf_too_small;
        if (ptr >= end) goto json_emit_buf_too_small;
        json_emit_char('}', &ptr, end);
    }

    if (json_emit_caveats_finish(&ptr, end) < 0) goto json_emit_buf_too_small;
    if (json_emit_required_field(0, ENC_B64, TYPE_SIGNATURE, &M->signature, &ptr, end) < 0) goto json_emit_buf_too_small;
    if (json_emit_finish(&ptr, end) < 0) goto json_emit_buf_too_small;
    return ptr - data;

json_emit_buf_too_small:
    *err = MACAROON_BUF_TOO_SMALL;
    return 0;
}
