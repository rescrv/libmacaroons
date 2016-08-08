/* Copyright (c) 2014, Robert Escriva
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
#include <string.h>

/* macaroons */
#include "constants.h"
#include "packet.h"
#include "v1.h"

#pragma GCC diagnostic ignored "-Wcast-qual"

enum encoding
{
    ENCODING_RAW,
    ENCODING_BASE64,
    ENCODING_HEX
};

static size_t
encoded_size(enum encoding encoding, size_t data_sz)
{
    switch (encoding)
    {
    case ENCODING_HEX:
        return data_sz * 2;
    case ENCODING_BASE64:
        return (data_sz + 2) / 3 * 4;
    case ENCODING_RAW:
        return data_sz;
    default:
        assert(0);
    }
}

static size_t
macaroon_inner_size_hint(const struct macaroon* M)
{
    size_t i;
    size_t sz = PACKET_SIZE(LOCATION, M->location.size)
              + PACKET_SIZE(IDENTIFIER, M->identifier.size)
              + PACKET_SIZE(SIGNATURE, M->signature.size);

    assert(M);
    VALIDATE(M);

    for (i = 0; i < M->num_caveats; ++i)
    {
        sz += PACKET_SIZE(CID, M->caveats[i].cid.size);
        sz += PACKET_SIZE(VID, M->caveats[i].vid.size);
        sz += PACKET_SIZE(CL, M->caveats[i].cl.size);
    }

    return sz;
}

static size_t
macaroon_inner_size_hint_ascii(const struct macaroon* M)
{
    size_t i;
    size_t sz = PACKET_SIZE(LOCATION, M->location.size)
              + PACKET_SIZE(IDENTIFIER, M->identifier.size)
              + PACKET_SIZE(SIGNATURE, encoded_size(ENCODING_HEX, M->signature.size));

    assert(M);
    VALIDATE(M);

    for (i = 0; i < M->num_caveats; ++i)
    {
        sz += PACKET_SIZE(CID, M->caveats[i].cid.size);
        sz += PACKET_SIZE(VID, encoded_size(ENCODING_BASE64, M->caveats[i].vid.size));
        sz += PACKET_SIZE(CL, M->caveats[i].cl.size);
    }

    return sz;
}

size_t
macaroon_serialize_size_hint_v1(const struct macaroon* M)
{
    return encoded_size(ENCODING_BASE64, macaroon_inner_size_hint(M)) + 1;
}

int
macaroon_serialize_v1(const struct macaroon* M,
                      char* data, size_t data_sz,
                      enum macaroon_returncode* err)
{
    const size_t sz = macaroon_serialize_size_hint_v1(M);
    size_t i;
    unsigned char* tmp = NULL;
    unsigned char* ptr = NULL;
    int rc = 0;

    if (data_sz < sz)
    {
        *err = MACAROON_BUF_TOO_SMALL;
        return -1;
    }

    tmp = malloc(sizeof(unsigned char) * sz);

    if (!tmp)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    ptr = tmp;
    ptr = serialize_slice_as_packet(LOCATION, LOCATION_SZ, &M->location, ptr);
    ptr = serialize_slice_as_packet(IDENTIFIER, IDENTIFIER_SZ, &M->identifier, ptr);

    for (i = 0; i < M->num_caveats; ++i)
    {
        if (M->caveats[i].cid.size)
        {
            ptr = serialize_slice_as_packet(CID, CID_SZ, &M->caveats[i].cid, ptr);
        }

        if (M->caveats[i].vid.size)
        {
            ptr = serialize_slice_as_packet(VID, VID_SZ, &M->caveats[i].vid, ptr);
        }

        if (M->caveats[i].cl.size)
        {
            ptr = serialize_slice_as_packet(CL, CL_SZ, &M->caveats[i].cl, ptr);
        }
    }

    ptr = serialize_slice_as_packet(SIGNATURE, SIGNATURE_SZ, &M->signature, ptr);
    rc = b64_ntop(tmp, ptr - tmp, data, data_sz);
    free(tmp);

    if (rc < 0)
    {
        *err = MACAROON_BUF_TOO_SMALL;
        return -1;
    }

    return 0;
}

struct macaroon*
macaroon_deserialize_v1(const char* _data, const size_t _data_sz, enum macaroon_returncode* err)
{
    size_t num_pkts = 0;
    struct packet pkt = EMPTY_PACKET;
    unsigned char* data = NULL;
    const unsigned char* end = NULL;
    const unsigned char* rptr = NULL;
    unsigned char* wptr = NULL;
    const unsigned char* tmp = NULL;
    const unsigned char* sig;
    const unsigned char* key;
    const unsigned char* val;
    size_t data_sz;
    size_t key_sz;
    size_t val_sz;
    int b64_sz;
    struct macaroon* M;

    data = malloc(sizeof(unsigned char) * _data_sz);

    if (!data)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    b64_sz = b64_pton(_data, data, _data_sz);

    if (b64_sz <= 0)
    {
        *err = MACAROON_INVALID;
        free(data);
        return NULL;
    }

    if (data[0] == '{')
    {
        *err = MACAROON_NO_JSON_SUPPORT;
        free(data);
        return NULL;
    }

    data_sz = b64_sz;
    rptr = data;
    end = rptr + data_sz;

    while (rptr && rptr < end)
    {
        rptr = parse_packet(rptr, end, &pkt);
        ++num_pkts;
    }

    if (!rptr || num_pkts < 3)
    {
        *err = MACAROON_INVALID;
        free(data);
        return NULL;
    }

    assert(num_pkts < data_sz);
    M = macaroon_malloc((num_pkts - 3/*loc,id,sig*/), data_sz, &wptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        free(data);
        return NULL;
    }

    rptr = data;
    *err = MACAROON_INVALID;

    /* location */
    if (copy_if_parses(&rptr, end, parse_location_packet, &M->location, &wptr) < 0)
    {
        free(M);
        free(data);
        return NULL;
    }

    /* identifier */
    if (copy_if_parses(&rptr, end, parse_identifier_packet, &M->identifier, &wptr) < 0)
    {
        free(M);
        free(data);
        return NULL;
    }

    M->num_caveats = 0;

    while (1)
    {
        tmp = parse_packet(rptr, end, &pkt);

        if (parse_kv_packet(&pkt, &key, &key_sz, &val, &val_sz) < 0)
        {
            break;
        }

        if (key_sz == CID_SZ && memcmp(key, CID, CID_SZ) == 0)
        {
            if (M->caveats[M->num_caveats].cid.size)
            {
                ++M->num_caveats;
            }

            wptr = copy_to_slice(val, val_sz, &M->caveats[M->num_caveats].cid, wptr);
        }
        else if (key_sz == VID_SZ && memcmp(key, VID, VID_SZ) == 0)
        {
            if (M->caveats[M->num_caveats].vid.size)
            {
                free(M);
                free(data);
                return NULL;
            }

            wptr = copy_to_slice(val, val_sz, &M->caveats[M->num_caveats].vid, wptr);
        }
        else if (key_sz == CL_SZ && memcmp(key, CL, CL_SZ) == 0)
        {
            if (M->caveats[M->num_caveats].cl.size)
            {
                free(M);
                free(data);
                return NULL;
            }

            wptr = copy_to_slice(val, val_sz, &M->caveats[M->num_caveats].cl, wptr);
        }
        else
        {
            break;
        }

        /* advance to the next packet */
        rptr = tmp;
    }

    /* catch the tail packet */
    if (M->caveats[M->num_caveats].cid.size)
    {
        ++M->num_caveats;
    }

    /* signature */
    rptr = parse_packet(rptr, end, &pkt);
    assert(rptr);

    if (parse_signature_packet(&pkt, &sig) < 0)
    {
        free(M);
        free(data);
        return NULL;
    }

    wptr = copy_to_slice(sig, MACAROON_HASH_BYTES, &M->signature, wptr);

    if (macaroon_validate(M) < 0)
    {
        free(M);
        free(data);
        return NULL;
    }

    free(data);
    *err = MACAROON_SUCCESS;
    return M;
}

size_t
macaroon_inspect_size_hint_v1(const struct macaroon* M)
{
    /* TODO why the extra MACAROON_HASH_BYTES here? */
    return macaroon_inner_size_hint_ascii(M) + MACAROON_HASH_BYTES;
}

/*
 * encode encodes the given data, putting
 * the resulting data and size into result and result_sz.
 * On return, if *result != data, the caller is
 * responsible for freeing it.
 */
static int
encode(enum encoding encoding, 
       const unsigned char* val, size_t val_sz,
       const unsigned char** result, size_t* result_sz,
       enum macaroon_returncode* err)
{
    char* enc;
    int enc_sz;
    if (encoding == ENCODING_RAW) {
        *result = val;
        *result_sz = val_sz;
        return 0;
    }
    enc_sz = encoded_size(encoding, val_sz);
    enc = malloc(enc_sz + 1);
    if (enc == NULL)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }
    switch (encoding)
    {
    case ENCODING_BASE64:
        enc_sz = b64_ntop(val, val_sz, enc, enc_sz + 1);
        if (enc_sz < 0)
        {
            *err = MACAROON_BUF_TOO_SMALL;
            return -1;
        }
        break;
    case ENCODING_HEX:
        macaroon_bin2hex(val, val_sz, enc);
        break;
    case ENCODING_RAW: /* should never get here */
    default:
        assert(0);
    }
    *result = (const unsigned char*)enc;
    *result_sz = enc_sz;
    return 0;
}

static char*
inspect_packet(const char* key,
               const struct slice* from,
               enum encoding encoding,
               char* ptr, char* ptr_end,
               enum macaroon_returncode *err)
{
    const unsigned char* enc_val = NULL;
    size_t key_sz = strlen(key);
    size_t enc_sz = 0;
    size_t total_sz = 0;
    if (encode(encoding, from->data, from->size, &enc_val, &enc_sz, err) < 0)
    {
        return NULL;
    }
    total_sz = key_sz + 1 + enc_sz + 1;
    assert(ptr_end >= ptr);
    assert(total_sz <= (size_t)(ptr_end - ptr));

    memmove(ptr, key, key_sz);
    ptr[key_sz] = ' ';
    memmove(ptr + key_sz + 1, enc_val, enc_sz);
    ptr[key_sz + 1 + enc_sz] = '\n';

    if (enc_val != from->data)
    {
        free((void *)enc_val);
    }
    return ptr + total_sz;
}

int
macaroon_inspect_v1(const struct macaroon* M,
                    char* data, size_t data_sz,
                    enum macaroon_returncode* err)
{
    const size_t sz = macaroon_inspect_size_hint(M);
    size_t i = 0;
    char* ptr = data;
    char* ptr_end = data + data_sz;

    if (data_sz < sz)
    {
        *err = MACAROON_BUF_TOO_SMALL;
        return -1;
    }

    ptr = inspect_packet(LOCATION, &M->location, ENCODING_RAW, ptr, ptr_end, err);
    if (ptr == NULL)
    {
        return -1;
    }
    ptr = inspect_packet(IDENTIFIER, &M->identifier, ENCODING_RAW, ptr, ptr_end, err);
    if (ptr == NULL)
    {
        return -1;
    }

    for (i = 0; i < M->num_caveats; ++i)
    {
        if (M->caveats[i].cid.size)
        {
            ptr = inspect_packet(CID, &M->caveats[i].cid, ENCODING_RAW, ptr, ptr_end, err);
            if (ptr == NULL)
            {
                return -1;
            }
        }

        if (M->caveats[i].vid.size)
        {
            ptr = inspect_packet(VID, &M->caveats[i].vid, ENCODING_BASE64, ptr, ptr_end, err);
            if (ptr == NULL)
            {
                return -1;
            }
        }

        if (M->caveats[i].cl.size)
        {
            ptr = inspect_packet(CL, &M->caveats[i].cl, ENCODING_RAW, ptr, ptr_end, err);
            if (ptr == NULL)
            {
                return -1;
            }
        }
    }

    ptr = inspect_packet(SIGNATURE, &M->signature, ENCODING_HEX, ptr, ptr_end, err);
    if (ptr == NULL)
    {
        return -1;
    }
    /* Replace final newline with terminator. */
    ptr[-1] = '\0';
    return 0;
}
