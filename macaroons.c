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

/* C */
#include <assert.h>
#include <stdio.h>
#include <string.h>

/* json */
#ifdef MACAROONS_JSON_SUPPORT
#include <json/json.h>
#endif

/* macaroons */
#include "base64.h"
#include "constants.h"
#include "macaroons.h"
#include "packet.h"
#include "port.h"

#ifdef PARANOID_MACAROONS
#define VALIDATE(M) assert(macaroon_validate(M) == 0);
#else
#define VALIDATE(M) do {} while (0)
#endif

#define MACAROON_API __attribute__ ((visibility ("default")))

#if MACAROON_HASH_BYTES != MACAROON_SECRET_KEY_BYTES
#error bad constants
#endif

#if MACAROON_HASH_BYTES != MACAROON_SUGGESTED_SECRET_LENGTH
#error bad constants
#endif

struct caveat
{
    struct packet cid;
    struct packet vid;
    struct packet cl;
};

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

struct macaroon
{
    /* the location packet */
    struct packet location;
    /* the identifier packet */
    struct packet identifier;
    /* the signature packet */
    struct packet signature;
    /* zero or more caveats */
    size_t num_caveats;
    struct caveat caveats[1];
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

/* Allocate a new macaroon with space for "num_caveats" caveats and a body of
 * "body_data" bytes.  Returns a ptr to a contiguous set of "body_data" bytes to
 * which the callee may write.
 */
static struct macaroon*
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

/* cumulative packet size, excluding the signature packet */
static size_t
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

    sz = PACKET_SIZE(LOCATION, location_sz)
       + PACKET_SIZE(IDENTIFIER, id_sz)
       + PACKET_SIZE(SIGNATURE, MACAROON_HASH_BYTES);
    M = macaroon_malloc(0, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    ptr = create_location_packet(location, location_sz, &M->location, ptr);
    ptr = create_identifier_packet(id, id_sz, &M->identifier, ptr);
    ptr = create_signature_packet(hash, MACAROON_HASH_BYTES, &M->signature, ptr);
    VALIDATE(M);
    return M;
}

static int
generate_derived_key(const unsigned char* variable_key,
                     size_t variable_key_sz,
                     unsigned char* derived_key)
{
    unsigned char genkey[MACAROON_HASH_BYTES];
    macaroon_memzero(genkey, MACAROON_HASH_BYTES);
    memmove(genkey, "macaroons-key-generator", sizeof("macaroons-key-generator"));
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
    const unsigned char* key;
    unsigned char hash[MACAROON_HASH_BYTES];
    size_t i;
    size_t sz;
    struct macaroon* M;
    unsigned char* ptr;
    assert(predicate_sz < MACAROON_MAX_STRLEN);
    assert(N->signature.data && N->signature.size > PACKET_PREFIX);

    if (N->num_caveats + 1 > MACAROON_MAX_CAVEATS)
    {
        *err = MACAROON_TOO_MANY_CAVEATS;
        return NULL;
    }

    if (parse_signature_packet(&N->signature, &key) < 0)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    if (macaroon_hash1(key, predicate, predicate_sz, hash) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    sz  = macaroon_body_size(N);
    sz += PACKET_SIZE(CID_SZ, predicate_sz);
    sz += PACKET_SIZE(SIGNATURE, MACAROON_HASH_BYTES);
    M = macaroon_malloc(N->num_caveats + 1, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    M->num_caveats = N->num_caveats + 1;
    ptr = copy_packet(&N->location, &M->location, ptr);
    ptr = copy_packet(&N->identifier, &M->identifier, ptr);

    for (i = 0; i < N->num_caveats; ++i)
    {
        ptr = copy_packet(&N->caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_packet(&N->caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_packet(&N->caveats[i].cl,  &M->caveats[i].cl,  ptr);
    }

    ptr = create_cid_packet(predicate, predicate_sz,
                            &M->caveats[M->num_caveats - 1].cid, ptr);
    ptr = create_signature_packet(hash, MACAROON_HASH_BYTES, &M->signature, ptr);
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
    const unsigned char *old_sig;
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
    assert(N->signature.data && N->signature.size > PACKET_PREFIX);
    VALIDATE(N);

    if (N->num_caveats + 1 > MACAROON_MAX_CAVEATS)
    {
        *err = MACAROON_TOO_MANY_CAVEATS;
        return NULL;
    }

    /*
     * note that MACAROON_HASH_BYTES is the same as
     * MACAROON_SECRET_KEY_BYTES, so the signature is also good to use
      * as an encoding key
     */
    if (parse_signature_packet(&N->signature, &old_sig) < 0)
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

    if (macaroon_secretbox(old_sig, enc_nonce, enc_plaintext,
                MACAROON_SECRET_TEXT_ZERO_BYTES + MACAROON_HASH_BYTES,
                enc_ciphertext) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    /* copy the (nonce, vid) pair into vid */
    memmove(vid, enc_nonce, MACAROON_SECRET_NONCE_BYTES);
    memmove(vid + MACAROON_SECRET_NONCE_BYTES,
            enc_ciphertext + MACAROON_SECRET_BOX_ZERO_BYTES,
            VID_NONCE_KEY_SZ - MACAROON_SECRET_NONCE_BYTES);

    /* calculate the new signature */
    if (macaroon_hash2(old_sig, vid, VID_NONCE_KEY_SZ, id, id_sz, new_sig) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    sz  = macaroon_body_size(N);
    sz += PACKET_SIZE(CID_SZ, id_sz);
    sz += PACKET_SIZE(VID_SZ, VID_NONCE_KEY_SZ);
    sz += PACKET_SIZE(CL_SZ, location_sz);
    sz += PACKET_SIZE(SIGNATURE, MACAROON_HASH_BYTES);
    M = macaroon_malloc(N->num_caveats + 1, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    M->num_caveats = N->num_caveats + 1;
    ptr = copy_packet(&N->location, &M->location, ptr);
    ptr = copy_packet(&N->identifier, &M->identifier, ptr);

    for (i = 0; i < N->num_caveats; ++i)
    {
        ptr = copy_packet(&N->caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_packet(&N->caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_packet(&N->caveats[i].cl,  &M->caveats[i].cl,  ptr);
    }

    ptr = create_cid_packet(id, id_sz, &M->caveats[M->num_caveats - 1].cid, ptr);
    ptr = create_vid_packet(vid, VID_NONCE_KEY_SZ, &M->caveats[M->num_caveats - 1].vid, ptr);
    ptr = create_cl_packet(location, location_sz, &M->caveats[M->num_caveats - 1].cl, ptr);
    ptr = create_signature_packet(new_sig, MACAROON_HASH_BYTES, &M->signature, ptr);
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
    int rc = 0;
    size_t idx = 0;
    unsigned count = 0;
    VALIDATE(M);

    for (idx = 0; idx < M->num_caveats; ++idx)
    {
        if (M->caveats[idx].vid.size > 0 && M->caveats[idx].cl.size > 0)
        {
            if (count == which)
            {
                rc = parse_cid_packet(&M->caveats[idx].cid, identifier, identifier_sz);
                assert(rc == 0);
                rc = parse_cl_packet(&M->caveats[idx].cl, location, location_sz);
                assert(rc == 0);
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
    const unsigned char* Msig;
    const unsigned char* MPsig;
    struct macaroon* B;
    unsigned char* ptr;
    unsigned char hash[MACAROON_HASH_BYTES];

    VALIDATE(M);
    VALIDATE(D);

    if (parse_signature_packet(&M->signature, &Msig) < 0 ||
        parse_signature_packet(&D->signature, &MPsig) < 0)
    {
        *err = MACAROON_INVALID;
        return NULL;
    }

    if (macaroon_bind(Msig, MPsig, hash) < 0)
    {
        *err = MACAROON_HASH_FAILED;
        return NULL;
    }

    B = macaroon_copy(D, err);

    if (!B)
    {
        return NULL;
    }

    ptr = (unsigned char*) B->signature.data;
    ptr = create_signature_packet(hash, MACAROON_HASH_BYTES, &B->signature, ptr);
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
    fail |= parse_cid_packet(&C->cid, &pred.data, &pred.size);

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
    size_t midx = 0;
    size_t tidx = 0;
    struct predicate cav;
    struct predicate vid;
    struct predicate mac;
    size_t sz;

    cav.data = NULL;
    cav.size = 0;
    fail |= parse_cid_packet(&C->cid, &cav.data, &cav.size);
    tree[tree_idx] = MS_sz;

    for (midx = 0; midx < MS_sz; ++midx)
    {
        mac.data = NULL;
        mac.size = 0;
        fail |= parse_identifier_packet(&MS[midx]->identifier, &mac.data, &mac.size);
        sz = cav.size < mac.size ? cav.size : mac.size;

        if (macaroon_memcmp(cav.data, mac.data, sz) == 0 && cav.size == mac.size)
        {
            tree[tree_idx] = midx;
        }

        for (tidx = 0; tidx < tree_idx; ++tidx)
        {
            fail |= tree[tidx] == tree[tree_idx];
        }
    }

    if (tree[tree_idx] < MS_sz)
    {
        /* zero everything */
        macaroon_memzero(enc_key, sizeof(enc_key));
        macaroon_memzero(enc_plaintext, sizeof(enc_plaintext));
        macaroon_memzero(enc_ciphertext, sizeof(enc_ciphertext));

        vid.data = vid_data;
        vid.size = sizeof(vid_data);
        fail |= parse_vid_packet(&C->vid, &vid.data, &vid.size);
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
        fail |= macaroon_verify_inner(V, MS[tree[tree_idx]], TM,
                                      enc_plaintext + MACAROON_SECRET_TEXT_ZERO_BYTES,
                                      MACAROON_HASH_BYTES,
                                      MS, MS_sz, err, tree, tree_idx + 1);
    }
    else
    {
        fail = -1;
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

    data = NULL;
    data_sz = 0;
    tree_fail |= parse_identifier_packet(&M->identifier, &data, &data_sz);
    tree_fail |= macaroon_hmac(key, key_sz, data, data_sz, csig);

    for (cidx = 0; cidx < M->num_caveats; ++cidx)
    {
        if (M->caveats[cidx].vid.size == 0)
        {
            tree_fail |= macaroon_verify_inner_1st(V, M->caveats + cidx);
            /* move the signature and compute a new one */
            memmove(tmp, csig, MACAROON_HASH_BYTES);
            data = NULL;
            data_sz = 0;
            tree_fail |= parse_cid_packet(&M->caveats[cidx].cid, &data, &data_sz);
            tree_fail |= macaroon_hash1(tmp, data, data_sz, csig);
        }
        else
        {
            tree_fail |= macaroon_verify_inner_3rd(V, M->caveats + cidx, csig, TM, MS, MS_sz, err, tree, tree_idx);
            /* move the signature and compute a new one */
            memmove(tmp, csig, MACAROON_HASH_BYTES);
            data = NULL;
            data_sz = 0;
            tree_fail |= parse_cid_packet(&M->caveats[cidx].cid, &data, &data_sz);
            vdata = NULL;
            vdata_sz = 0;
            tree_fail |= parse_vid_packet(&M->caveats[cidx].vid, &vdata, &vdata_sz);
            tree_fail |= macaroon_hash2(tmp, vdata, vdata_sz, data, data_sz, csig);
        }
    }

    if (tree_idx > 0)
    {
        memmove(tmp, csig, MACAROON_HASH_BYTES);
        data = TM->signature.data;
        tree_fail |= parse_signature_packet(&TM->signature, &data);
        tree_fail |= macaroon_bind(data, tmp, csig);
    }

    data = M->signature.data;
    tree_fail |= parse_signature_packet(&M->signature, &data);
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
    int rc = 0;
    assert(M);
    VALIDATE(M);
    rc = parse_location_packet(&M->location, location, location_sz);
    assert(rc == 0);
}

MACAROON_API void
macaroon_identifier(const struct macaroon* M,
                    const unsigned char** identifier, size_t* identifier_sz)
{
    int rc = 0;
    assert(M);
    VALIDATE(M);
    rc = parse_identifier_packet(&M->identifier, identifier, identifier_sz);
    assert(rc == 0);
}

MACAROON_API void
macaroon_signature(const struct macaroon* M,
                   const unsigned char** signature, size_t* signature_sz)
{
    int rc = 0;
    assert(M);
    VALIDATE(M);
    rc = parse_signature_packet(&M->signature, signature);
    *signature_sz = MACAROON_HASH_BYTES;
    assert(rc == 0);
}

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

static size_t
macaroon_inner_size_hint(const struct macaroon* M)
{
    size_t i;
    size_t sz = M->location.size
              + M->identifier.size
              + M->signature.size;

    assert(M);
    VALIDATE(M);

    for (i = 0; i < M->num_caveats; ++i)
    {
        sz += M->caveats[i].cid.size;
        sz += M->caveats[i].vid.size;
        sz += M->caveats[i].cl.size;
    }

    return sz;
}

static size_t
macaroon_inner_size_hint_ascii(const struct macaroon* M)
{
    size_t i;
    size_t sz = M->location.size
              + M->identifier.size
              + encoded_size(ENCODING_HEX, M->signature.size);

    assert(M);
    VALIDATE(M);

    for (i = 0; i < M->num_caveats; ++i)
    {
        sz += M->caveats[i].cid.size;
        sz += encoded_size(ENCODING_BASE64, M->caveats[i].vid.size);
        sz += M->caveats[i].cl.size;
    }

    return sz;
}


MACAROON_API size_t
macaroon_serialize_size_hint(const struct macaroon* M)
{
    return encoded_size(ENCODING_BASE64, macaroon_inner_size_hint(M)) + 1;
}

MACAROON_API int
macaroon_serialize(const struct macaroon* M,
                   char* data, size_t data_sz,
                   enum macaroon_returncode* err)
{
    const size_t sz = macaroon_serialize_size_hint(M);
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
    ptr = serialize_packet(&M->location, ptr);
    ptr = serialize_packet(&M->identifier, ptr);

    for (i = 0; i < M->num_caveats; ++i)
    {
        if (M->caveats[i].cid.size)
        {
            ptr = serialize_packet(&M->caveats[i].cid, ptr);
        }

        if (M->caveats[i].vid.size)
        {
            ptr = serialize_packet(&M->caveats[i].vid, ptr);
        }

        if (M->caveats[i].cl.size)
        {
            ptr = serialize_packet(&M->caveats[i].cl, ptr);
        }
    }

    ptr = serialize_packet(&M->signature, ptr);
    rc = b64_ntop(tmp, ptr - tmp, data, data_sz);
    free(tmp);

    if (rc < 0)
    {
        *err = MACAROON_BUF_TOO_SMALL;
        return -1;
    }

    return 0;
}

#ifdef MACAROONS_JSON_SUPPORT

MACAROON_API size_t
macaroon_serialize_json_size_hint(const struct macaroon* M)
{
    /* the inner size hint captures the length of each packet, which for
     * kv-packets are the key, payload, and a little extra.
     */
    size_t sz = macaroon_inner_size_hint_ascii(M);
    /* we then add the overheads imposed by JSON */
    /* every key-value pair has some quotes, colons, commas, spacing */
    sz += (4 + M->num_caveats * 3) * 8;
    /* every caveat is an object */
    sz += M->num_caveats * 2;
    /* there's some overhead for the list and object notation */
    sz += 4;
    /* finally, we're b64'ing this, so account for that */
    sz = encoded_size(ENCODING_BASE64, sz);
    return sz;
}

static int
json_help_add_strings(struct json_object* obj,
                      const char* key, const char* val, size_t val_sz,
                      enum macaroon_returncode* err)
{
    struct json_object* jval = NULL;
    jval = json_object_new_string_len(val, val_sz);

    if (!jval)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    json_object_object_add(obj, key, jval);
    return 0;
}

static int
json_help_add_kv_packet(struct json_object* obj,
                            const struct packet* kv_pkt,
             enum encoding encoding,
                            enum macaroon_returncode* err)
{
    const unsigned char* enc_val = NULL;
    const unsigned char* key = NULL;
    const unsigned char* val = NULL;
    size_t enc_sz = 0;
    size_t key_sz = 0;
    size_t val_sz = 0;
    char* jkey = NULL;
    int rc = 0;

    if (parse_kv_packet(kv_pkt, &key, &key_sz, &val, &val_sz) < 0)
    {
        *err = MACAROON_INVALID;
        return -1;
    }
    if (encode(encoding, val, val_sz, &enc_val, &enc_sz, err) < 0)
    {
        return -1;
    }

    jkey = strndup((const char*)key, key_sz);
    if (!jkey)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    rc = json_help_add_strings(obj, jkey, (const char*)enc_val, enc_sz, err);
    free(jkey);
    if (enc_val != val)
    {
        free((void*)enc_val);
    }
    return rc;
}

MACAROON_API int
macaroon_serialize_json(const struct macaroon* M,
                        char* data, size_t data_sz,
                        enum macaroon_returncode* err)
{
    struct json_object* obj = NULL;
    struct json_object* arr = NULL;
    struct json_object* cav = NULL;
    const char* ser = NULL;
    size_t ser_sz = 0;
    size_t idx = 0;

    obj = json_object_new_object();

    if (!obj)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    arr = json_object_new_array();

    if (!arr)
    {
        json_object_put(obj);
        *err = MACAROON_OUT_OF_MEMORY;
        return -1;
    }

    json_object_object_add(obj, "caveats", arr);

    if (json_help_add_kv_packet(obj, &M->location, ENCODING_RAW, err) < 0 ||
        json_help_add_kv_packet(obj, &M->identifier, ENCODING_RAW, err) < 0 ||
        json_help_add_kv_packet(obj, &M->signature, ENCODING_HEX, err) < 0)
    {
        json_object_put(obj);
        return -1;
    }

    for (idx = 0; idx < M->num_caveats; ++idx)
    {
        cav = json_object_new_object();

        if (!cav ||
            json_object_array_add(arr, cav) < 0)
        {
            json_object_put(obj);
            *err = MACAROON_OUT_OF_MEMORY;
            return -1;
        }

        if ((M->caveats[idx].cid.size > 0 &&
             json_help_add_kv_packet(cav, &M->caveats[idx].cid, ENCODING_RAW, err) < 0) ||
            (M->caveats[idx].vid.size > 0 &&
             json_help_add_kv_packet(cav, &M->caveats[idx].vid, ENCODING_BASE64, err) < 0) ||
            (M->caveats[idx].cl.size > 0 &&
             json_help_add_kv_packet(cav, &M->caveats[idx].cl, ENCODING_RAW, err) < 0))
        {
            json_object_put(obj);
            return -1;
        }
    }

    ser = json_object_to_json_string_ext(obj, JSON_C_TO_STRING_PLAIN);
    ser_sz = strlen(ser);

    if (b64_ntop((const unsigned char*)ser, ser_sz, data, data_sz) < 0)
    {
        json_object_put(obj);
        *err = MACAROON_BUF_TOO_SMALL;
        return -1;
    }

    json_object_put(obj);
    return 0;
}

/*
 * decode decodes the given string, putting
 * the resulting data and size into result and result_sz.
 * On return, if *result != data, the caller is
 * responsible for freeing it.
 *
 * str is assumed to be null-terminated - str_sz
 * should not include the terminating zero.
 */
static int
decode(enum encoding encoding, 
       const unsigned char* str, size_t str_sz,
       const unsigned char** result, size_t* result_sz,
       enum macaroon_returncode* err)
{
    unsigned char* dec_val;
    size_t dec_sz;
    switch (encoding)
    {
    case ENCODING_RAW:
        *result = str;
        *result_sz = str_sz;
        break;

    case ENCODING_BASE64:
        dec_val = malloc(str_sz);
        if (!dec_val)
        {
            *err = MACAROON_OUT_OF_MEMORY;
            return -1;
        }
  
        dec_sz = b64_pton(str, dec_val, str_sz);
        if (dec_sz <= 0)
        {
            *err = MACAROON_INVALID;
            free(dec_val);
            return -1;
        }
        *result = dec_val;
        *result_sz = dec_sz;
        break;
        
    case ENCODING_HEX:
        dec_sz = str_sz / 2;
        dec_val = malloc(dec_sz + 1);
        if (!dec_val)
        {
            *err = MACAROON_OUT_OF_MEMORY;
            return -1;
        }
        if (macaroon_hex2bin(str, str_sz, dec_val) < 0)
        {
            *err = MACAROON_INVALID;
            free(dec_val);
            return -1;
        }
        *result = dec_val;
        *result_sz = dec_sz;
        break;

    default:
        assert(0);
    }
    return 0;
}

static int
json_help_copy_kv_packet(struct json_object* obj,
                         const char* key,
                         unsigned char* (*f)(const unsigned char*, size_t, struct packet*, unsigned char*),
                         struct packet* pkt,
                         enum encoding encoding,
                         unsigned char** wptr,
                         enum macaroon_returncode* err)
{
    struct json_object* child = NULL;
    const unsigned char* str = NULL;
    const unsigned char* dec = NULL;
    size_t dec_sz;
    size_t str_sz = 0;
    if (!json_object_is_type(obj, json_type_object))
    {
        *err = MACAROON_INVALID;
        return -1;
    }

    if (!json_object_object_get_ex(obj, key, &child) ||
        !json_object_is_type(child, json_type_string))
    {
        *err = MACAROON_INVALID;
        return -1;
    }
    str = (const unsigned char*)json_object_get_string(child);
    str_sz = json_object_get_string_len(child);
    if (decode(encoding, str, str_sz, &dec, &dec_sz, err) < 0)
    {
        return -1;
    }
 
    *wptr = f(dec, dec_sz, pkt, *wptr);
    if (dec != str)
    {
        free((void*)dec);
    }
    return 0;
}

static int
json_help_copy_signature(struct json_object* obj,
                         struct packet* pkt,
                         unsigned char** wptr)
{
    struct json_object* child = NULL;
    const char* str = NULL;
    size_t str_sz = 0;
    unsigned char sig[MACAROON_HASH_BYTES];

    assert(json_object_is_type(obj, json_type_object));

    if (!json_object_object_get_ex(obj, SIGNATURE, &child) ||
        !json_object_is_type(child, json_type_string))
    {
        return -1;
    }

    str = json_object_get_string(child);
    str_sz = json_object_get_string_len(child);

    if (str_sz != 2 * MACAROON_HASH_BYTES ||
        macaroon_hex2bin(str, str_sz, sig) < 0)
    {
        return -1;
    }

    *wptr = create_signature_packet(sig, MACAROON_HASH_BYTES, pkt, *wptr);
    return 0;
}

MACAROON_API struct macaroon*
macaroon_deserialize_json(const char* data, size_t data_sz,
                          enum macaroon_returncode* err)
{
    struct json_object* obj = NULL;
    struct json_object* arr = NULL;
    struct json_object* cav = NULL;
    struct json_tokener* tok = json_tokener_new();
    size_t idx = 0;
    int arr_sz = 0;
    struct macaroon* M = NULL;
    unsigned char* ptr = NULL;

    if (!tok)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    obj = json_tokener_parse_ex(tok, data, data_sz);

    if (!obj)
    {
        json_tokener_free(tok);
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    if ((tok->char_offset < 0 || (size_t)tok->char_offset < data_sz) ||
        (json_object_object_get_ex(obj, "caveats", &arr) != TRUE) ||
        (json_object_get_type(arr) != json_type_array) ||
        ((arr_sz = json_object_array_length(arr)) < 0))
    {
        json_object_put(obj);
        json_tokener_free(tok);
        *err = MACAROON_INVALID;
        return NULL;
    }

    M = macaroon_malloc(arr_sz, data_sz, &ptr);

    if (!M)
    {
        json_object_put(obj);
        json_tokener_free(tok);
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    if (json_help_copy_kv_packet(obj, LOCATION, create_location_packet, &M->location, ENCODING_RAW, &ptr, err) < 0 ||
        json_help_copy_kv_packet(obj, IDENTIFIER, create_identifier_packet, &M->identifier, ENCODING_RAW, &ptr, err) < 0 ||
        json_help_copy_kv_packet(obj, SIGNATURE, create_signature_packet, &M->signature, ENCODING_HEX, &ptr, err) < 0)
    {
        free(M);
        json_object_put(obj);
        json_tokener_free(tok);
        return NULL;
    }

    for (idx = 0; idx < (size_t)arr_sz; ++idx)
    {
        cav = json_object_array_get_idx(arr, idx);
        
        /* TODO deserialize caveat vid and location. */
        if (!cav || !json_object_is_type(cav, json_type_object))
        {
            free(M);
            json_object_put(obj);
            json_tokener_free(tok);
            *err = MACAROON_INVALID;
            return NULL;
        }
          
        if (json_help_copy_kv_packet(cav, CID, create_cid_packet, &M->caveats[idx].cid, ENCODING_RAW, &ptr, err) < 0)
        {
            free(M);
            json_object_put(obj);
            json_tokener_free(tok);
            return NULL;
        }
    }

    M->num_caveats = arr_sz;
    json_object_put(obj);
    json_tokener_free(tok);

    if (macaroon_validate(M) < 0)
    {
        free(M);
        *err = MACAROON_INVALID;
        return NULL;
    }

    return M;
}

#else /* MACAROONS_JSON_SUPPORT */

MACAROON_API size_t
macaroon_serialize_json_size_hint(const struct macaroon* M)
{
    (void) M;
    return 1;
}

MACAROON_API int
macaroon_serialize_json(const struct macaroon* M,
                        char* data, size_t data_sz,
                        enum macaroon_returncode* err)
{
    (void) M;
    (void) data;
    (void) data_sz;
    *err = MACAROON_NO_JSON_SUPPORT;
    return -1;
}

#endif /* MACAROONS_JSON_SUPPORT */

MACAROON_API struct macaroon*
macaroon_deserialize(const char* _data, enum macaroon_returncode* err)
{
    size_t num_pkts = 0;
    struct packet pkt = EMPTY_PACKET;
    const size_t _data_sz = strlen(_data);
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

#ifdef MACAROONS_JSON_SUPPORT
    if (data[0] == '{')
    {
        M = macaroon_deserialize_json((const char*)data, b64_sz, err);
        free(data);
        return M;
    }
#else
    if (data[0] == '{')
    {
        *err = MACAROON_NO_JSON_SUPPORT;
        return NULL;
    }
#endif

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

            wptr = copy_packet(&pkt, &M->caveats[M->num_caveats].cid, wptr);
        }
        else if (key_sz == VID_SZ && memcmp(key, VID, VID_SZ) == 0)
        {
            if (M->caveats[M->num_caveats].vid.size)
            {
                free(M);
                free(data);
                return NULL;
            }

            wptr = copy_packet(&pkt, &M->caveats[M->num_caveats].vid, wptr);
        }
        else if (key_sz == CL_SZ && memcmp(key, CL, CL_SZ) == 0)
        {
            if (M->caveats[M->num_caveats].cl.size)
            {
                free(M);
                free(data);
                return NULL;
            }

            wptr = copy_packet(&pkt, &M->caveats[M->num_caveats].cl, wptr);
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

    wptr = copy_packet(&pkt, &M->signature, wptr);

    if (macaroon_validate(M) < 0)
    {
        free(M);
        free(data);
        return NULL;
    }

    *err = MACAROON_SUCCESS;
    return M;
}

MACAROON_API size_t
macaroon_inspect_size_hint(const struct macaroon* M)
{
    /* TODO why the extra MACAROON_HASH_BYTES here? */
    return macaroon_inner_size_hint_ascii(M) + MACAROON_HASH_BYTES;
}

static char*
inspect_packet(const struct packet* from,
               enum encoding encoding,
               char* ptr, char* ptr_end,
               enum macaroon_returncode *err)
{
    const unsigned char* key = NULL;
    const unsigned char* val = NULL;
    const unsigned char* enc_val = NULL;
    size_t key_sz = 0;
    size_t val_sz = 0;
    size_t enc_sz = 0;
    size_t total_sz = 0;
    int rc;
    rc = parse_kv_packet(from, &key, &key_sz, &val, &val_sz);
    assert(rc == 0);
    if (encode(encoding, val, val_sz, &enc_val, &enc_sz, err) < 0)
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

    if (enc_val != val)
    {
        free((void *)enc_val);
    }
    return ptr + total_sz;
}

MACAROON_API int
macaroon_inspect(const struct macaroon* M,
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

    ptr = inspect_packet(&M->location, ENCODING_RAW, ptr, ptr_end, err);
    if (ptr == NULL)
    {
        return -1;
    }
    ptr = inspect_packet(&M->identifier, ENCODING_RAW, ptr, ptr_end, err);
    if (ptr == NULL)
    {
        return -1;
    }

    for (i = 0; i < M->num_caveats; ++i)
    {
        if (M->caveats[i].cid.size)
        {
            ptr = inspect_packet(&M->caveats[i].cid, ENCODING_RAW, ptr, ptr_end, err);
            if (ptr == NULL)
            {
                return -1;
            }
        }

        if (M->caveats[i].vid.size)
        {
            ptr = inspect_packet(&M->caveats[i].vid, ENCODING_BASE64, ptr, ptr_end, err);
            if (ptr == NULL)
            {
                return -1;
            }
        }

        if (M->caveats[i].cl.size)
        {
            ptr = inspect_packet(&M->caveats[i].cl, ENCODING_RAW, ptr, ptr_end, err);
            if (ptr == NULL)
            {
                return -1;
            }
        }
    }

    ptr = inspect_packet(&M->signature, ENCODING_HEX, ptr, ptr_end, err);
    if (ptr == NULL)
    {
        return -1;
    }
    /* Replace final newline with terminator. */
    ptr[-1] = '\0';
    return 0;
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

    sz  = macaroon_body_size(N);
    sz += PACKET_SIZE(SIGNATURE, MACAROON_HASH_BYTES);
    M = macaroon_malloc(N->num_caveats + 1, sz, &ptr);

    if (!M)
    {
        *err = MACAROON_OUT_OF_MEMORY;
        return NULL;
    }

    M->num_caveats = N->num_caveats;
    ptr = copy_packet(&N->location, &M->location, ptr);
    ptr = copy_packet(&N->identifier, &M->identifier, ptr);

    for (i = 0; i < N->num_caveats; ++i)
    {
        ptr = copy_packet(&N->caveats[i].cid, &M->caveats[i].cid, ptr);
        ptr = copy_packet(&N->caveats[i].vid, &M->caveats[i].vid, ptr);
        ptr = copy_packet(&N->caveats[i].cl,  &M->caveats[i].cl,  ptr);
    }

    ptr = copy_packet(&N->signature, &M->signature, ptr);
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
    ret |= packet_cmp(&M->location, &N->location);
    ret |= packet_cmp(&M->identifier, &N->identifier);
    ret |= packet_cmp(&M->signature, &N->signature);

    num_caveats = M->num_caveats < N->num_caveats ?
                  M->num_caveats : N->num_caveats;

    for (i = 0; i < num_caveats; ++i)
    {
        ret |= packet_cmp(&M->caveats[i].cid,
                          &N->caveats[i].cid);
        ret |= packet_cmp(&M->caveats[i].vid,
                          &N->caveats[i].vid);
        ret |= packet_cmp(&M->caveats[i].cl,
                          &N->caveats[i].cl);
    }

    return ret;
}
