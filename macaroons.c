/* Copyright (c) 2014-2016, Robert Escriva
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

/* C */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_BSD_STDLIB_H
#include <bsd/stdlib.h>
#endif
#include <string.h>
#ifdef HAVE_LIBUTIL_H
#include <libutil.h>
#elif defined HAVE_BSD_LIBUTIL_H
#include <bsd/libutil.h>
#elif defined HAVE_OSX_LIBUTIL_H
#include <util.h>
#else
#error portability problem
#endif

/* macaroons */
#include "macaroons.h"
#include "constants.h"
#include "macaroons.h"
#include "macaroons-inner.h"
#include "port.h"
#include "slice.h"
#include "v1.h"
#include "v2.h"

#if MACAROON_HASH_BYTES != MACAROON_SECRET_KEY_BYTES
#error bad constants
#endif

#if MACAROON_HASH_BYTES != MACAROON_SUGGESTED_SECRET_LENGTH
#error bad constants
#endif

#define XSTR(x) #x
#define STR(x) XSTR(x)
#define STRINGIFY(x) case (x): return XSTR(x);

struct predicate
{
    const unsigned char* data;
    size_t size;
    unsigned char* alloc;
};

struct verifier_callback
{
    int (*func)(void* f, const unsigned char* pred, size_t pred_sz);
    void* ptr;
};

struct macaroon_verifier
{
    struct predicate* predicates;
    size_t predicates_sz;
    size_t predicates_cap;
    struct verifier_callback* verifier_callbacks;
    size_t verifier_callbacks_sz;
    size_t verifier_callbacks_cap;
};

MACAROON_API const char*
macaroon_error(enum macaroon_returncode err)
{
    switch (err)
    {
        STRINGIFY(MACAROON_SUCCESS);
        STRINGIFY(MACAROON_OUT_OF_MEMORY);
        STRINGIFY(MACAROON_HASH_FAILED);
        STRINGIFY(MACAROON_INVALID);
        STRINGIFY(MACAROON_TOO_MANY_CAVEATS);
        STRINGIFY(MACAROON_CYCLE);
        STRINGIFY(MACAROON_BUF_TOO_SMALL);
        STRINGIFY(MACAROON_NOT_AUTHORIZED);
        STRINGIFY(MACAROON_NO_JSON_SUPPORT);
        STRINGIFY(MACAROON_UNSUPPORTED_FORMAT);
        default:
            return "unknown error";
    }
}

/* Allocate a new macaroon with space for "num_caveats" caveats and a body of
 * "body_data" bytes.  Returns via _ptr a contiguous set of "body_data" bytes to
 * which the callee may write.
 */
struct macaroon*
macaroon_malloc(const size_t num_caveats,
                const size_t body_data,
                unsigned char** _ptr)
{
    unsigned char* ptr = NULL;
    struct macaroon* M = NULL;
    const size_t additional_caveats = (num_caveats > 0) ? num_caveats - 1 : 0;
    const size_t sz = sizeof(struct macaroon) + body_data
                    + additional_caveats * sizeof(struct caveat);
    M = malloc(sz);

    if (!M)
    {
        return NULL;
    }

    macaroon_memzero(M, sz);
    ptr  = (unsigned char*) M;
    ptr += sizeof(struct macaroon);
    ptr += additional_caveats * sizeof(struct caveat);
    *_ptr = ptr;
    return M;
}

/* cumulative slice size, excluding the signature slice */
size_t
macaroon_body_size(const struct macaroon* M)
{
    size_t i = 0;
    size_t sz = M->location.size
              + M->identifier.size;

    for (i = 0; i < M->num_caveats; ++i)
    {
        sz += M->caveats[i].cid.size;
        sz += M->caveats[i].vid.size;
        sz += M->caveats[i].cl.size;
    }

    return sz;
}

MACAROON_API struct macaroon*
macaroon_create_raw(const unsigned char* location, size_t location_sz,
                    const unsigned char* key, size_t key_sz,
                    const unsigned char* id, size_t id_sz,
                    enum macaroon_returncode* err)
{
    unsigned char hash[MACAROON_HASH_BYTES];
    size_t sz;
    struct macaroon* M;
    unsigned char* ptr;
    assert(location_sz < MACAROON_MAX_STRLEN);
    assert(id_sz < MACAROON_MAX_STRLEN);
    assert(key_sz == MACAROON_SUGGESTED_SECRET_LENGTH);

    if (macaroon_hmac(key, key_sz, id, id_sz, hash) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    sz = location_sz + id_sz + MACAROON_HASH_BYTES;
    M = macaroon_malloc(0, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    ptr = copy_to_slice(location, location_sz, &M->location, ptr);
    ptr = copy_to_slice(id, id_sz, &M->identifier, ptr);
    ptr = copy_to_slice(hash, MACAROON_HASH_BYTES, &M->signature, ptr);
    VALIDATE(M);
    return M;
}

#define MACAROON_KEY_GENERATOR "macaroons-key-generator"

static int
generate_derived_key(const unsigned char* variable_key,
                     size_t variable_key_sz,
                     unsigned char* derived_key)
{
    unsigned char genkey[MACAROON_HASH_BYTES];
    macaroon_memzero(genkey, MACAROON_HASH_BYTES);
    assert(sizeof(MACAROON_KEY_GENERATOR) <= sizeof(genkey));
    memmove(genkey, MACAROON_KEY_GENERATOR, sizeof(MACAROON_KEY_GENERATOR));
    return macaroon_hmac(genkey, MACAROON_HASH_BYTES, variable_key, variable_key_sz, derived_key);
}

MACAROON_API struct macaroon*
macaroon_create(const unsigned char* location, size_t location_sz,
                const unsigned char* key, size_t key_sz,
                const unsigned char* id, size_t id_sz,
                enum macaroon_returncode* err)
{
    unsigned char derived_key[MACAROON_HASH_BYTES];

    if (generate_derived_key(key, key_sz, derived_key) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    return macaroon_create_raw(location, location_sz, derived_key, MACAROON_HASH_BYTES, id, id_sz, err);
}

MACAROON_API void
macaroon_destroy(struct macaroon* M)
{
    if (M)
    {
        free(M);
    }
}

MACAROON_API int
macaroon_validate(const struct macaroon* M)
{
    /* XXX */
    (void) M;
    return 0;
}

static int
macaroon_hash1(const unsigned char* key,
               const unsigned char* data1,
               size_t data1_sz,
               unsigned char* hash)
{
    return macaroon_hmac(key, MACAROON_HASH_BYTES, data1, data1_sz, hash);
}

MACAROON_API struct macaroon*
macaroon_add_first_party_caveat(const struct macaroon* N,
                                const unsigned char* predicate, size_t predicate_sz,
                                enum macaroon_returncode* err)
{
    unsigned char hash[MACAROON_HASH_BYTES];
    size_t i;
    size_t sz;
    struct macaroon* M;
    unsigned char* ptr;
    assert(predicate_sz < MACAROON_MAX_STRLEN);

    if (N->num_caveats + 1 > MACAROON_MAX_CAVEATS)
    {
        *err = MACAROON_TOO_MANY_CAVEATS;
        return NULL;
    }

    if (!N->signature.data || N->signature.size != MACAROON_HASH_BYTES)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    if (macaroon_hash1(N->signature.data, predicate, predicate_sz, hash) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    sz = macaroon_body_size(N) + predicate_sz + MACAROON_HASH_BYTES;
    M = macaroon_malloc(N->num_caveats + 1, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    M->num_caveats = N->num_caveats + 1;
    ptr = copy_slice(&N->location, &M->location, ptr);
    ptr = copy_slice(&N->identifier, &M->identifier, ptr);

    for (i = 0; i < N->num_caveats; ++i)
    {
        ptr = copy_slice(&N->caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_slice(&N->caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_slice(&N->caveats[i].cl,  &M->caveats[i].cl,  ptr);
    }

    ptr = copy_to_slice(predicate, predicate_sz,
                        &M->caveats[M->num_caveats - 1].cid, ptr);
    ptr = copy_to_slice(hash, MACAROON_HASH_BYTES, &M->signature, ptr);
    VALIDATE(M);
    return M;
}

static int
macaroon_hash2(const unsigned char* key,
               const unsigned char* data1,
               size_t data1_sz,
               const unsigned char* data2,
               size_t data2_sz,
               unsigned char* hash)
{
    int rc = 0;
    unsigned char tmp[2 * MACAROON_HASH_BYTES];
    rc |= macaroon_hmac(key, MACAROON_HASH_BYTES, data1, data1_sz, tmp);
    rc |= macaroon_hmac(key, MACAROON_HASH_BYTES, data2, data2_sz, tmp + MACAROON_HASH_BYTES);
    rc |= macaroon_hmac(key, MACAROON_HASH_BYTES, tmp, 2 * MACAROON_HASH_BYTES, hash);
    return rc;
}

#define SECRET_BOX_OVERHEAD \
    (MACAROON_SECRET_TEXT_ZERO_BYTES \
     - MACAROON_SECRET_BOX_ZERO_BYTES)

#define VID_NONCE_KEY_SZ \
    (MACAROON_SECRET_NONCE_BYTES \
     + MACAROON_HASH_BYTES \
     + SECRET_BOX_OVERHEAD)

#if MACAROON_SECRET_TEXT_ZERO_BYTES < MACAROON_SECRET_BOX_ZERO_BYTES
#error bad constants
#endif

MACAROON_API struct macaroon*
macaroon_add_third_party_caveat_raw(const struct macaroon* N,
                                    const unsigned char* location, size_t location_sz,
                                    const unsigned char* key, size_t key_sz,
                                    const unsigned char* id, size_t id_sz,
                                    enum macaroon_returncode* err)
{
    unsigned char new_sig[MACAROON_HASH_BYTES];
    unsigned char enc_nonce[MACAROON_SECRET_NONCE_BYTES];
    unsigned char enc_plaintext[MACAROON_SECRET_TEXT_ZERO_BYTES + MACAROON_HASH_BYTES];
    unsigned char enc_ciphertext[MACAROON_SECRET_BOX_ZERO_BYTES + MACAROON_HASH_BYTES];
    unsigned char vid[VID_NONCE_KEY_SZ];
    size_t i;
    size_t sz;
    struct macaroon* M;
    unsigned char* ptr;
    assert(location_sz < MACAROON_MAX_STRLEN);
    assert(id_sz < MACAROON_MAX_STRLEN);
    assert(key_sz == MACAROON_SUGGESTED_SECRET_LENGTH);
    VALIDATE(N);

    if (N->num_caveats + 1 > MACAROON_MAX_CAVEATS)
    {
        *err = MACAROON_TOO_MANY_CAVEATS;
        return NULL;
    }

    /*
     * note that MACAROON_HASH_BYTES is necessarily the same as
     * MACAROON_SECRET_KEY_BYTES, so the signature is also good to use
      * as an encoding key
     */
    if (!N->signature.data || N->signature.size != MACAROON_HASH_BYTES)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    macaroon_randombytes(enc_nonce, sizeof(enc_nonce));
    macaroon_memzero(enc_plaintext, sizeof(enc_plaintext));
    macaroon_memzero(enc_ciphertext, sizeof(enc_ciphertext));

    /* now encrypt the key to give us vid */
    memmove(enc_plaintext + MACAROON_SECRET_TEXT_ZERO_BYTES, key,
            key_sz < MACAROON_HASH_BYTES ? key_sz : MACAROON_HASH_BYTES);

    if (macaroon_secretbox(N->signature.data, enc_nonce, enc_plaintext,
                MACAROON_SECRET_TEXT_ZERO_BYTES + MACAROON_HASH_BYTES,
                enc_ciphertext) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    /* copy the (nonce, vid) pair into vid */
    memmove(vid, enc_nonce, MACAROON_SECRET_NONCE_BYTES);
    memmove(vid           + MACAROON_SECRET_NONCE_BYTES,
            enc_ciphertext + MACAROON_SECRET_BOX_ZERO_BYTES,
            VID_NONCE_KEY_SZ - MACAROON_SECRET_NONCE_BYTES);

    /* calculate the new signature */
    if (macaroon_hash2(N->signature.data, vid, VID_NONCE_KEY_SZ, id, id_sz, new_sig) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    sz = macaroon_body_size(N)
       + id_sz
       + VID_NONCE_KEY_SZ
       + location_sz
       + MACAROON_HASH_BYTES;
    M = macaroon_malloc(N->num_caveats + 1, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    M->num_caveats = N->num_caveats + 1;
    ptr = copy_slice(&N->location, &M->location, ptr);
    ptr = copy_slice(&N->identifier, &M->identifier, ptr);

    for (i = 0; i < N->num_caveats; ++i)
    {
        ptr = copy_slice(&N->caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_slice(&N->caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_slice(&N->caveats[i].cl,  &M->caveats[i].cl,  ptr);
    }

    ptr = copy_to_slice(id, id_sz, &M->caveats[M->num_caveats - 1].cid, ptr);
    ptr = copy_to_slice(vid, VID_NONCE_KEY_SZ, &M->caveats[M->num_caveats - 1].vid, ptr);
    ptr = copy_to_slice(location, location_sz, &M->caveats[M->num_caveats - 1].cl, ptr);
    ptr = copy_to_slice(new_sig, MACAROON_HASH_BYTES, &M->signature, ptr);
    VALIDATE(M);
    return M;
}

MACAROON_API struct macaroon*
macaroon_add_third_party_caveat(const struct macaroon* N,
                                const unsigned char* location, size_t location_sz,
                                const unsigned char* key, size_t key_sz,
                                const unsigned char* id, size_t id_sz,
                                enum macaroon_returncode* err)
{
    unsigned char derived_key[MACAROON_HASH_BYTES];

    if (generate_derived_key(key, key_sz, derived_key) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    return macaroon_add_third_party_caveat_raw(N, location, location_sz, derived_key, MACAROON_HASH_BYTES, id, id_sz, err);
}

static int
macaroon_bind(const unsigned char* Msig,
              const unsigned char* MPsig,
              unsigned char* bound)
{
    unsigned char key[MACAROON_HASH_BYTES];
    macaroon_memzero(key, MACAROON_HASH_BYTES);
    return macaroon_hash2(key, Msig, MACAROON_HASH_BYTES,
                          MPsig, MACAROON_HASH_BYTES, bound);
}

MACAROON_API unsigned
macaroon_num_caveats(const struct macaroon* M)
{
    VALIDATE(M);
    return M->num_caveats;
}

MACAROON_API unsigned
macaroon_num_first_party_caveats(const struct macaroon* M)
{
    size_t idx = 0;
    unsigned count = 0;
    VALIDATE(M);

    for (idx = 0; idx < M->num_caveats; ++idx)
    {
        if (M->caveats[idx].vid.size == 0 && M->caveats[idx].cl.size == 0)
        {
            ++count;
        }
    }

    return count;
}

MACAROON_API unsigned
macaroon_num_third_party_caveats(const struct macaroon* M)
{
    size_t idx = 0;
    unsigned count = 0;
    VALIDATE(M);

    for (idx = 0; idx < M->num_caveats; ++idx)
    {
        if (M->caveats[idx].vid.size > 0 && M->caveats[idx].cl.size > 0)
        {
            ++count;
        }
    }

    return count;
}

MACAROON_API int
macaroon_third_party_caveat(const struct macaroon* M, unsigned which,
                            const unsigned char** location, size_t* location_sz,
                            const unsigned char** identifier, size_t* identifier_sz)
{
    size_t idx = 0;
    unsigned count = 0;
    VALIDATE(M);

    for (idx = 0; idx < M->num_caveats; ++idx)
    {
        if (M->caveats[idx].vid.size > 0 && M->caveats[idx].cl.size > 0)
        {
            if (count == which)
            {
                unstruct_slice(&M->caveats[idx].cid, identifier, identifier_sz);
                unstruct_slice(&M->caveats[idx].cl, location, location_sz);
                return 0;
            }

            ++count;
        }
    }

    return -1;
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"

MACAROON_API struct macaroon*
macaroon_prepare_for_request(const struct macaroon* M,
                             const struct macaroon* D,
                             enum macaroon_returncode* err)
{
    struct macaroon* B;
    unsigned char hash[MACAROON_HASH_BYTES];

    VALIDATE(M);
    VALIDATE(D);

    if (!M->signature.data || M->signature.size != MACAROON_HASH_BYTES ||
        !D->signature.data || D->signature.size != MACAROON_HASH_BYTES)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    if (macaroon_bind(M->signature.data, D->signature.data, hash) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    B = macaroon_copy(D, err);

    if (!B)
    {
        return NULL;
    }

    memmove((unsigned char*)B->signature.data, hash, MACAROON_HASH_BYTES);
    VALIDATE(B);
    return B;
}

#pragma GCC diagnostic pop

MACAROON_API struct macaroon_verifier*
macaroon_verifier_create()
{
    struct macaroon_verifier* V;
    V = malloc(sizeof(struct macaroon_verifier));

    if (!V)
    {
        return NULL;
    }

    memset(V, 0, sizeof(struct macaroon_verifier));
    V->predicates = NULL;
    V->predicates_sz = 0;
    V->predicates_cap = 0;
    return V;
}

MACAROON_API void
macaroon_verifier_destroy(struct macaroon_verifier* V)
{
    size_t idx = 0;

    if (V)
    {
        for (idx = 0; idx < V->predicates_sz; ++idx)
        {
            if (V->predicates[idx].alloc)
            {
                free(V->predicates[idx].alloc);
            }
        }

        if (V->predicates)
        {
            free(V->predicates);
        }

        if (V->verifier_callbacks)
        {
            free(V->verifier_callbacks);
        }

        free(V);
    }
}

MACAROON_API int
macaroon_verifier_satisfy_exact(struct macaroon_verifier* V,
                                const unsigned char* predicate, size_t predicate_sz,
                                enum macaroon_returncode* err)
{
    struct predicate* tmp = NULL;

    if (V->predicates_sz == V->predicates_cap)
    {
        V->predicates_cap = V->predicates_cap < 8 ? 8 :
                            V->predicates_cap + (V->predicates_cap >> 1);
        tmp = realloc(V->predicates, V->predicates_cap * sizeof(struct predicate));

        if (!tmp)
        {
            *err = MACAROON_OUT_OF_MEMORY;
            return -1;
        }

        V->predicates = tmp;
    }

    assert(V->predicates_sz < V->predicates_cap);
    tmp = &V->predicates[V->predicates_sz];
    tmp->data = tmp->alloc = malloc(sizeof(unsigned char) * predicate_sz);
    tmp->size = predicate_sz;

    if (!tmp->data)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    memmove(tmp->alloc, predicate, predicate_sz);
    ++V->predicates_sz;
    assert(V->predicates_sz <= V->predicates_cap);
    return 0;
}

MACAROON_API int
macaroon_verifier_satisfy_general(struct macaroon_verifier* V,
                                  int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz),
                                  void* f, enum macaroon_returncode* err)
{
    struct verifier_callback* tmp = NULL;

    if (V->verifier_callbacks_sz == V->verifier_callbacks_cap)
    {
        V->verifier_callbacks_cap = V->verifier_callbacks_cap < 8 ? 8 :
                                    V->verifier_callbacks_cap +
                                    (V->verifier_callbacks_cap >> 1);
        tmp = realloc(V->verifier_callbacks,
                      V->verifier_callbacks_cap * sizeof(struct verifier_callback));

        if (!tmp)
        {
            *err = MACAROON_OUT_OF_MEMORY;
            return -1;
        }

        V->verifier_callbacks = tmp;
    }

    assert(V->verifier_callbacks_sz < V->verifier_callbacks_cap);
    tmp = &V->verifier_callbacks[V->verifier_callbacks_sz];
    tmp->func = general_check;
    tmp->ptr = f;
    ++V->verifier_callbacks_sz;
    assert(V->verifier_callbacks_sz <= V->verifier_callbacks_cap);
    return 0;
}

static int
macaroon_verify_inner(const struct macaroon_verifier* V,
                      const struct macaroon* M,
                      const struct macaroon* TM,
                      const unsigned char* key, size_t key_sz,
                      struct macaroon** MS, size_t MS_sz,
                      enum macaroon_returncode* err,
                      size_t* tree, size_t tree_idx);

static int
macaroon_verify_inner_1st(const struct macaroon_verifier* V,
                          const struct caveat* C)
{
    int fail = 0;
    int found = 0;
    size_t sz = 0;
    size_t idx = 0;
    struct predicate pred;
    struct predicate* poss;
    struct verifier_callback* vcb;

    pred.data = NULL;
    pred.size = 0;
    unstruct_slice(&C->cid, &pred.data, &pred.size);

    for (idx = 0; idx < V->predicates_sz; ++idx)
    {
        poss = &V->predicates[idx];
        sz = pred.size < poss->size ?  pred.size : poss->size;
        found |= macaroon_memcmp(pred.data, poss->data, sz) == 0 &&
                 pred.size == poss->size;
    }

    for (idx = 0; idx < V->verifier_callbacks_sz; ++idx)
    {
        vcb = &V->verifier_callbacks[idx];
        found |= vcb->func(vcb->ptr, pred.data, pred.size) == 0;
    }

    return (!fail && found) ? 0 : -1;
}

static int
macaroon_verify_inner_3rd(const struct macaroon_verifier* V,
                          const struct caveat* C,
                          const unsigned char* sig,
                          const struct macaroon* TM,
                          struct macaroon** MS, size_t MS_sz,
                          enum macaroon_returncode* err,
                          size_t* tree, size_t tree_idx)
{
    unsigned char enc_key[MACAROON_SECRET_KEY_BYTES];
    const unsigned char *enc_nonce;
    unsigned char enc_plaintext[MACAROON_SECRET_TEXT_ZERO_BYTES + MACAROON_HASH_BYTES];
    unsigned char enc_ciphertext[MACAROON_SECRET_BOX_ZERO_BYTES + MACAROON_HASH_BYTES + SECRET_BOX_OVERHEAD];
    unsigned char vid_data[VID_NONCE_KEY_SZ];

    int fail = 0;
    int inner = -1;
    size_t midx = 0;
    size_t tidx = 0;
    struct predicate cav;
    struct predicate vid;
    struct predicate mac;
    size_t sz;

    cav.data = NULL;
    cav.size = 0;
    unstruct_slice(&C->cid, &cav.data, &cav.size);
    tree[tree_idx] = MS_sz;

    for (midx = 0; midx < MS_sz; ++midx)
    {
        mac.data = NULL;
        mac.size = 0;
        unstruct_slice(&MS[midx]->identifier, &mac.data, &mac.size);
        sz = cav.size < mac.size ? cav.size : mac.size;

        if (macaroon_memcmp(cav.data, mac.data, sz) == 0 && cav.size == mac.size)
        {
            tree[tree_idx] = midx;
            /* zero everything */
            macaroon_memzero(enc_key, sizeof(enc_key));
            macaroon_memzero(enc_plaintext, sizeof(enc_plaintext));
            macaroon_memzero(enc_ciphertext, sizeof(enc_ciphertext));

            vid.data = vid_data;
            vid.size = sizeof(vid_data);
            unstruct_slice(&C->vid, &vid.data, &vid.size);
            assert(vid.size == VID_NONCE_KEY_SZ);
            /*
             * the nonce is in the first MACAROON_SECRET_NONCE_BYTES
             * of the vid; the ciphertext is in the rest of it.
             */
            enc_nonce = vid.data;
            /* fill in the ciphertext */
            memmove(enc_ciphertext + MACAROON_SECRET_BOX_ZERO_BYTES,
                    vid.data + MACAROON_SECRET_NONCE_BYTES,
                    vid.size - MACAROON_SECRET_NONCE_BYTES);
            /* now get the plaintext */
            fail |= macaroon_secretbox_open(sig, enc_nonce, enc_ciphertext,
                                            sizeof(enc_ciphertext),
                                            enc_plaintext);
            inner &= macaroon_verify_inner(V, MS[tree[tree_idx]], TM,
                                          enc_plaintext + MACAROON_SECRET_TEXT_ZERO_BYTES,
                                          MACAROON_HASH_BYTES,
                                          MS, MS_sz, err, tree, tree_idx + 1);
        }

        for (tidx = 0; tidx < tree_idx; ++tidx)
        {
            fail |= tree[tidx] == tree[tree_idx];
        }
    }

    if (tree[tree_idx] >= MS_sz)
    {
        fail = -1;
    }
    else
    {
        fail |= inner;
    }

    return fail;
}

int
macaroon_verify_inner(const struct macaroon_verifier* V,
                      const struct macaroon* M,
                      const struct macaroon* TM,
                      const unsigned char* key, size_t key_sz,
                      struct macaroon** MS, size_t MS_sz,
                      enum macaroon_returncode* err,
                      size_t* tree, size_t tree_idx)
{
    size_t cidx = 0;
    int tree_fail = 0;
    const unsigned char* data = NULL;
    size_t data_sz = 0;
    const unsigned char* vdata = NULL;
    size_t vdata_sz = 0;
    unsigned char tmp[MACAROON_HASH_BYTES];
    unsigned char csig[MACAROON_HASH_BYTES];

    assert(M);
    assert(TM);

    if (macaroon_validate(M) < 0)
    {
        *err = MACAROON_INVALID;
        return -1;
    }

    if (tree_idx > MS_sz)
    {
        *err = MACAROON_CYCLE;
        return -1;
    }

    tree_fail = 0;
    tree_fail |= macaroon_hmac(key, key_sz, M->identifier.data, M->identifier.size, csig);

    for (cidx = 0; cidx < M->num_caveats; ++cidx)
    {
        if (M->caveats[cidx].vid.size == 0)
        {
            tree_fail |= macaroon_verify_inner_1st(V, M->caveats + cidx);
            /* move the signature and compute a new one */
            memmove(tmp, csig, MACAROON_HASH_BYTES);
            data = NULL;
            data_sz = 0;
            unstruct_slice(&M->caveats[cidx].cid, &data, &data_sz);
            tree_fail |= macaroon_hash1(tmp, data, data_sz, csig);
        }
        else
        {
            tree_fail |= macaroon_verify_inner_3rd(V, M->caveats + cidx, csig, TM, MS, MS_sz, err, tree, tree_idx);
            /* move the signature and compute a new one */
            memmove(tmp, csig, MACAROON_HASH_BYTES);
            data = NULL;
            data_sz = 0;
            unstruct_slice(&M->caveats[cidx].cid, &data, &data_sz);
            vdata = NULL;
            vdata_sz = 0;
            unstruct_slice(&M->caveats[cidx].vid, &vdata, &vdata_sz);
            tree_fail |= macaroon_hash2(tmp, vdata, vdata_sz, data, data_sz, csig);
        }
    }

    if (tree_idx > 0)
    {
        memmove(tmp, csig, MACAROON_HASH_BYTES);
        data = TM->signature.data;
        tree_fail |= TM->signature.size ^ MACAROON_HASH_BYTES;
        tree_fail |= macaroon_bind(data, tmp, csig);
    }

    data = M->signature.data;
    tree_fail |= M->signature.size ^ MACAROON_HASH_BYTES;
    tree_fail |= macaroon_memcmp(data, csig, MACAROON_HASH_BYTES);
    return tree_fail;
}

MACAROON_API int
macaroon_verify_raw(const struct macaroon_verifier* V,
                    const struct macaroon* M,
                    const unsigned char* key, size_t key_sz,
                    struct macaroon** MS, size_t MS_sz,
                    enum macaroon_returncode* err)
{
    int rc = 0;
    size_t i = 0;
    size_t* tree = malloc((MS_sz + 1) * sizeof(size_t));

    if (!tree)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    for (i = 0; i < MS_sz; ++i)
    {
        tree[i] = MS_sz;
    }

    tree[MS_sz] = MS_sz;

    assert(key_sz == MACAROON_SUGGESTED_SECRET_LENGTH);
    rc = macaroon_verify_inner(V, M, M, key, key_sz,
                               MS, MS_sz, err, tree, 0);
    if (rc)
    {
        *err = MACAROON_NOT_AUTHORIZED;
    }

    free(tree);
    return rc;
}

MACAROON_API int
macaroon_verify(const struct macaroon_verifier* V,
                const struct macaroon* M,
                const unsigned char* key, size_t key_sz,
                struct macaroon** MS, size_t MS_sz,
                enum macaroon_returncode* err)
{
    unsigned char derived_key[MACAROON_HASH_BYTES];

    if (generate_derived_key(key, key_sz, derived_key) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return -1;
    }

    return macaroon_verify_raw(V, M, derived_key, MACAROON_HASH_BYTES, MS, MS_sz, err);
}

MACAROON_API void
macaroon_location(const struct macaroon* M,
                  const unsigned char** location, size_t* location_sz)
{
    assert(M);
    VALIDATE(M);
    unstruct_slice(&M->location, location, location_sz);
}

MACAROON_API void
macaroon_identifier(const struct macaroon* M,
                    const unsigned char** identifier, size_t* identifier_sz)
{
    assert(M);
    VALIDATE(M);
    unstruct_slice(&M->identifier, identifier, identifier_sz);
}

MACAROON_API void
macaroon_signature(const struct macaroon* M,
                   const unsigned char** signature, size_t* signature_sz)
{
    assert(M);
    VALIDATE(M);
    unstruct_slice(&M->signature, signature, signature_sz);
}

MACAROON_API size_t
macaroon_serialize_size_hint(const struct macaroon* M,
                             enum macaroon_format f)
{
    switch (f)
    {
        case MACAROON_V1:
            return macaroon_serialize_size_hint_v1(M);
        case MACAROON_V2:
            return macaroon_serialize_size_hint_v2(M);
        case MACAROON_V2J:
#ifdef MACAROONS_JSON
            return macaroon_serialize_size_hint_v2j(M);
#endif
        default:
            return 0;
    }
}

MACAROON_API size_t
macaroon_serialize(const struct macaroon* M,
                   enum macaroon_format f,
                   unsigned char* buf, size_t buf_sz,
                   enum macaroon_returncode* err)
{
    switch (f)
    {
        case MACAROON_V1:
            if (macaroon_serialize_v1(M, (char*)buf, buf_sz, err) < 0) return 0;
            return strlen((char*)buf);
        case MACAROON_V2:
            return macaroon_serialize_v2(M, buf, buf_sz, err);
        case MACAROON_V2J:
#ifdef MACAROONS_JSON
            return macaroon_serialize_v2j(M, buf, buf_sz, err);
#else
            *err = MACAROON_NO_JSON_SUPPORT;
            return 0;
#endif
        default:
            *err = MACAROON_INVALID;
            return 0;
    }
}

static const char v1_chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/-_";

MACAROON_API struct macaroon*
macaroon_deserialize(const unsigned char* data, size_t data_sz,
                     enum macaroon_returncode* err)
{
    if (data_sz == 0)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    if (strchr(v1_chars, data[0]))
    {
        return macaroon_deserialize_v1((const char*)data, data_sz, err);
    }

    if (data[0] == '{')
    {
#ifdef MACAROONS_JSON
        return macaroon_deserialize_v2j(data, data_sz, err);
#else
        *err = MACAROON_NO_JSON_SUPPORT;
        return 0;
#endif
    }
    else if (data[0] == '\x02')
    {
        return macaroon_deserialize_v2(data, data_sz, err);
    }
    else
    {
        *err = MACAROON_INVALID;
        return NULL;
    }
}

MACAROON_API size_t
macaroon_inspect_size_hint(const struct macaroon* M)
{
    return macaroon_inspect_size_hint_v1(M);
}

MACAROON_API int
macaroon_inspect(const struct macaroon* M,
                 char* data, size_t data_sz,
                 enum macaroon_returncode* err)
{
    return macaroon_inspect_v1(M, data, data_sz, err);
}

MACAROON_API struct macaroon*
macaroon_copy(const struct macaroon* N,
              enum macaroon_returncode* err)
{
    size_t i;
    size_t sz;
    struct macaroon* M;
    unsigned char* ptr;

    assert(N);
    VALIDATE(N);

    sz  = macaroon_body_size(N) + MACAROON_HASH_BYTES;
    M = macaroon_malloc(N->num_caveats, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    M->num_caveats = N->num_caveats;
    ptr = copy_slice(&N->location, &M->location, ptr);
    ptr = copy_slice(&N->identifier, &M->identifier, ptr);

    for (i = 0; i < N->num_caveats; ++i)
    {
        ptr = copy_slice(&N->caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_slice(&N->caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_slice(&N->caveats[i].cl,  &M->caveats[i].cl,  ptr);
    }

    ptr = copy_slice(&N->signature, &M->signature, ptr);
    VALIDATE(M);
    return M;
}

MACAROON_API int
macaroon_cmp(const struct macaroon* M, const struct macaroon* N)
{
    size_t i = 0;
    size_t num_caveats = 0;
    unsigned long long ret = 0;

    assert(M);
    assert(N);
    VALIDATE(M);
    VALIDATE(N);

    ret |= M->num_caveats ^ N->num_caveats;
    ret |= slice_cmp(&M->location, &N->location);
    ret |= slice_cmp(&M->identifier, &N->identifier);
    ret |= slice_cmp(&M->signature, &N->signature);

    num_caveats = M->num_caveats < N->num_caveats ?
                  M->num_caveats : N->num_caveats;

    for (i = 0; i < num_caveats; ++i)
    {
        ret |= slice_cmp(&M->caveats[i].cid,
                         &N->caveats[i].cid);
        ret |= slice_cmp(&M->caveats[i].vid,
                         &N->caveats[i].vid);
        ret |= slice_cmp(&M->caveats[i].cl,
                         &N->caveats[i].cl);
    }

    return ret;
}
