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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* c */
#include <assert.h>
#include <stdint.h>
#include <string.h>

/* macaroons */
#include "constants.h"
#include "packet.h"
#include "port.h"

static unsigned char*
packet_memmove(unsigned char* ptr, const unsigned char* src, size_t sz)
{
    memmove(ptr, src, sz);
    return ptr + sz;
}

static unsigned char*
packet_header(size_t sz, unsigned char* ptr)
{
    static const char hex[] = "0123456789abcdef";
    assert(sz < 65536);
    ptr[0] = hex[(sz >> 12) & 15];
    ptr[1] = hex[(sz >> 8) & 15];
    ptr[2] = hex[(sz >> 4) & 15];
    ptr[3] = hex[(sz) & 15];
    assert(PACKET_PREFIX == 4); /* modify above on failure */
    return ptr + PACKET_PREFIX;
}

const unsigned char*
parse_packet(const unsigned char* ptr,
             const unsigned char* const end,
             struct packet* pkt)
{
    static const char hex[] = "0123456789abcdef";
    const char* tmp;
    uint32_t sz = 0;
    int i = 0;

    if (end - ptr < PACKET_PREFIX)
    {
        return NULL;
    }

    for (i = 0; i < PACKET_PREFIX; ++i)
    {
        sz <<= 4;
        tmp = strchr(hex, ptr[i]);

        if (!tmp)
        {
            return NULL;
        }

        sz |= tmp - hex;
    }

    if (end - ptr < sz)
    {
        return NULL;
    }

    pkt->data = ptr;
    pkt->size = sz;
    return ptr + sz;
}

int
packet_cmp(const struct packet* lhs,
           const struct packet* rhs)
{
    return macaroon_memcmp(lhs->data, rhs->data,
                           (lhs->size < rhs->size) ? lhs->size : rhs->size);
}

unsigned char*
create_kv_packet(const unsigned char* key, size_t key_sz,
                 const unsigned char* val, size_t val_sz,
                 struct packet* pkt, unsigned char* ptr)
{
    size_t sz = PACKET_PREFIX + 2 + key_sz + val_sz;

    pkt->data = ptr;
    pkt->size = sz;

    memset(ptr, 0, sz);
    ptr = packet_header(sz, ptr);
    ptr = packet_memmove(ptr, key, key_sz);
    *ptr = ' ';
    ++ptr;
    ptr = packet_memmove(ptr, val, val_sz);
    *ptr = '\n';
    ++ptr;
    return ptr;
}

int
parse_kv_packet(const struct packet* pkt,
                const unsigned char** key, size_t* key_sz,
                const unsigned char** val, size_t* val_sz)
{
    unsigned char* tmp = NULL;
    unsigned char prefix[PACKET_PREFIX];

    *key = NULL;
    *key_sz = 0;
    *val = NULL;
    *val_sz = 0;

    if (pkt->size > PACKET_MAX_SIZE)
    {
        return -1;
    }

    packet_header(pkt->size, prefix);

    if (pkt->size < PACKET_PREFIX + 2 ||
        memcmp(pkt->data, prefix, PACKET_PREFIX) != 0 ||
        pkt->data[pkt->size - 1] != '\n')
    {
        return -1;
    }

    tmp = memchr(pkt->data + PACKET_PREFIX, ' ', pkt->size - PACKET_PREFIX);

    if (!tmp)
    {
        return -1;
    }

    *key = pkt->data + PACKET_PREFIX;
    *key_sz = tmp - *key;

    *val = tmp + 1;
    *val_sz = pkt->size - PACKET_PREFIX - 2 - *key_sz;
    return 0;
}

unsigned char*
copy_packet(const struct packet* from,
            struct packet* to,
            unsigned char* ptr)
{
    memmove(ptr, from->data, from->size);
    to->data = ptr;
    to->size = from->size;
    return ptr + to->size;
}

unsigned char*
serialize_packet(const struct packet* from,
                 unsigned char* ptr)
{
    memmove(ptr, from->data, from->size);
    return ptr + from->size;
}

int
copy_if_parses(const unsigned char** rptr,
               const unsigned char* const end,
               int (*f)(const struct packet* pkt,
                        const unsigned char** s, size_t* s_sz),
               struct packet* to,
               unsigned char** wptr)
{
    const unsigned char* tmp;
    size_t tmp_sz;
    struct packet pkt;

    *rptr = parse_packet(*rptr, end, &pkt);

    if (!*rptr || f(&pkt, &tmp, &tmp_sz) < 0)
    {
        return -1;
    }

    *wptr = copy_packet(&pkt, to, *wptr);
    return 0;
}

unsigned char*
create_location_packet(const unsigned char* location, size_t location_sz,
                       struct packet* pkt, unsigned char* ptr)
{
    return create_kv_packet((const unsigned char*)LOCATION, LOCATION_SZ,
                            location, location_sz, pkt, ptr);
}

int
parse_location_packet(const struct packet* packet,
                      const unsigned char** location, size_t* location_sz)
{
    const unsigned char* key;
    const unsigned char* val;
    size_t key_sz;
    size_t val_sz;

    if (parse_kv_packet(packet, &key, &key_sz, &val, &val_sz) < 0)
    {
        return -1;
    }

    if (key_sz != LOCATION_SZ ||
        memcmp(key, LOCATION, LOCATION_SZ) != 0)
    {
        return -1;
    }

    *location = val;
    *location_sz = val_sz;
    return 0;
}

unsigned char*
create_identifier_packet(const unsigned char* identifier, size_t identifier_sz,
                         struct packet* pkt, unsigned char* ptr)
{
    return create_kv_packet((const unsigned char*)IDENTIFIER, IDENTIFIER_SZ,
                            identifier, identifier_sz, pkt, ptr);
}

int
parse_identifier_packet(const struct packet* packet,
                        const unsigned char** identifier, size_t* identifier_sz)
{
    const unsigned char* key;
    const unsigned char* val;
    size_t key_sz;
    size_t val_sz;

    if (parse_kv_packet(packet, &key, &key_sz, &val, &val_sz) < 0)
    {
        return -1;
    }

    if (key_sz != IDENTIFIER_SZ ||
        memcmp(key, IDENTIFIER, IDENTIFIER_SZ) != 0)
    {
        return -1;
    }

    *identifier = val;
    *identifier_sz = val_sz;
    return 0;
}

unsigned char*
create_signature_packet(const unsigned char* signature, size_t signature_sz,
                        struct packet* pkt, unsigned char* ptr)
{
    return create_kv_packet((const unsigned char*)SIGNATURE, SIGNATURE_SZ,
                            signature, signature_sz, pkt, ptr);
}

int
parse_signature_packet(const struct packet* packet,
                       const unsigned char** signature)
{
    const unsigned char* key;
    const unsigned char* val;
    size_t key_sz;
    size_t val_sz;

    if (parse_kv_packet(packet, &key, &key_sz, &val, &val_sz) < 0)
    {
        return -1;
    }

    if (key_sz != SIGNATURE_SZ ||
        val_sz != MACAROON_HASH_BYTES ||
        memcmp(key, SIGNATURE, SIGNATURE_SZ) != 0)
    {
        return -1;
    }

    *signature = val;
    return 0;
}

unsigned char*
create_cid_packet(const unsigned char* cid, size_t cid_sz,
                  struct packet* pkt, unsigned char* ptr)
{
    return create_kv_packet((const unsigned char*)CID, CID_SZ,
                            cid, cid_sz, pkt, ptr);
}

int
parse_cid_packet(const struct packet* packet,
                 const unsigned char** cid, size_t* cid_sz)
{
    const unsigned char* key;
    const unsigned char* val;
    size_t key_sz;
    size_t val_sz;

    if (parse_kv_packet(packet, &key, &key_sz, &val, &val_sz) < 0)
    {
        return -1;
    }

    if (key_sz != CID_SZ || memcmp(key, CID, CID_SZ) != 0)
    {
        return -1;
    }

    *cid = val;
    *cid_sz = val_sz;
    return 0;
}

unsigned char*
create_vid_packet(const unsigned char* vid, size_t vid_sz,
                  struct packet* pkt, unsigned char* ptr)
{
    return create_kv_packet((const unsigned char*)VID, VID_SZ,
                            vid, vid_sz, pkt, ptr);
}

int
parse_vid_packet(const struct packet* packet,
                 const unsigned char** vid, size_t* vid_sz)
{
    const unsigned char* key;
    const unsigned char* val;
    size_t key_sz;
    size_t val_sz;

    if (parse_kv_packet(packet, &key, &key_sz, &val, &val_sz) < 0)
    {
        return -1;
    }

    if (key_sz != VID_SZ || memcmp(key, VID, VID_SZ) != 0)
    {
        return -1;
    }

    *vid = val;
    *vid_sz = val_sz;
    return 0;
}

unsigned char*
create_cl_packet(const unsigned char* cl, size_t cl_sz,
                 struct packet* pkt, unsigned char* ptr)
{
    return create_kv_packet((const unsigned char*)CL, CL_SZ,
                            cl, cl_sz, pkt, ptr);
}

int
parse_cl_packet(const struct packet* packet,
                const unsigned char** cl, size_t* cl_sz)
{
    const unsigned char* key;
    const unsigned char* val;
    size_t key_sz;
    size_t val_sz;

    if (parse_kv_packet(packet, &key, &key_sz, &val, &val_sz) < 0)
    {
        return -1;
    }

    if (key_sz != CL_SZ || memcmp(key, CL, CL_SZ) != 0)
    {
        return -1;
    }

    *cl = val;
    *cl_sz = val_sz;
    return 0;
}
