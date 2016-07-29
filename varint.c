// This code is derived from code distributed as part of Google LevelDB.
// The original is available in leveldb as util/coding.cc.
// This file was retrieved Jul 15, 2013 by Robert Escriva and imported into
// libe.  This code is copied/modified from libe.

// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

/* C */
#include <stdint.h>
#include <stdlib.h>

/* macaroons */
#include "varint.h"

unsigned char*
packvarint(uint64_t v, unsigned char* ptr)
{
    const unsigned B = 128;

    while (v >= B)
    {
        *(ptr++) = (v & (B-1)) | B;
        v >>= 7;
    }

    *(ptr++) = (unsigned char)(v);
    return ptr;
}

const unsigned char*
unpackvarint(const unsigned char* ptr,
             const unsigned char* end,
             uint64_t* value)
{
    uint64_t result = 0;
    unsigned int shift;

    for (shift = 0; shift <= 63 && ptr < end; shift += 7)
    {
        uint64_t byte = *ptr & 0xff;
        ptr++;

        if (byte & 128)
        {
            // More bytes are present
            result |= ((byte & 127) << shift);
        }
        else
        {
            result |= (byte << shift);
            *value = result;
            return ptr;
        }
    }

    return NULL;
}

unsigned
varint_length(uint64_t v)
{
    int len = 1;

    while (v >= 128)
    {
        v >>= 7;
        len++;
    }

    return len;
}
