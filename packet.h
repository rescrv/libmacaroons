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

#ifndef macaroons_packet_h_
#define macaroons_packet_h_

/* C */
#include <stddef.h>

/* macaroons */
#include "slice.h"

#define PACKET_PREFIX 4
#define PACKET_SIZE(KEY, VAL) (PACKET_PREFIX + STRLENOF(KEY) + (VAL) + 2)
#define PACKET_MAX_SIZE 65535

#define NULL_PACKET {NULL, 0};
#define EMPTY_PACKET {(const unsigned char*)"0004", 4}

struct packet
{
    const unsigned char* data;
    size_t size;
};

const unsigned char*
parse_packet(const unsigned char* ptr,
             const unsigned char* const end,
             struct packet* pkt);

/* A key-value packet has this form:
 * <4 byte header><key><space><value><new-line>
 */
int
parse_kv_packet(const struct packet* pkt,
                const unsigned char** key, size_t* key_sz,
                const unsigned char** val, size_t* val_sz);

/* copy a packet to the memory pointed to by ptr */
unsigned char*
serialize_slice_as_packet(const char* key, size_t key_sz,
                          const struct slice* from,
                          unsigned char* ptr);
int
copy_if_parses(const unsigned char** rptr,
               const unsigned char* const end,
               int (*f)(const struct packet* pkt,
                        const unsigned char** s, size_t* s_sz),
               struct slice* to,
               unsigned char** wptr);

int parse_location_packet(const struct packet* pkt,
                          const unsigned char** location, size_t* location_sz);
int parse_identifier_packet(const struct packet* pkt,
                            const unsigned char** identifier, size_t* identifier_sz);
int parse_signature_packet(const struct packet* pkt,
                           const unsigned char** signature);
int parse_cid_packet(const struct packet* pkt,
                     const unsigned char** cid, size_t* cid_sz);
int parse_vid_packet(const struct packet* pkt,
                     const unsigned char** vid, size_t* vid_sz);
int parse_cl_packet(const struct packet* pkt,
                    const unsigned char** cl, size_t* cl_sz);

#endif /* macaroons_packet_h_ */
