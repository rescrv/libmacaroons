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
#include <string.h>

/* macaroons */
#include "port.h"
#include "slice.h"

unsigned char*
copy_to_slice(const unsigned char* data, size_t data_sz,
              struct slice* sl, unsigned char* ptr)
{
    memmove(ptr, data, data_sz);
    sl->data = ptr;
    sl->size = data_sz;
    return ptr + data_sz;
}

void
unstruct_slice(const struct slice* sl, const unsigned char** data, size_t* data_sz)
{
    *data = sl->data;
    *data_sz = sl->size;
}

unsigned char*
copy_slice(const struct slice* from,
           struct slice* to,
           unsigned char* ptr)
{
    return copy_to_slice(from->data, from->size, to, ptr);
}

int
slice_cmp(const struct slice* lhs,
          const struct slice* rhs)
{
    return macaroon_memcmp(lhs->data, rhs->data,
                           (lhs->size < rhs->size) ? lhs->size : rhs->size);
}
