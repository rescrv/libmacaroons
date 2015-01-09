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

#ifndef macaroons_h_
#define macaroons_h_

/* C */
#include <stdlib.h>

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

/* All byte strings must be less than this length.
 * Enforced via "assert" internally.
 * */
#define MACAROON_MAX_STRLEN 32768
/* Place a sane limit on the number of caveats */
#define MACAROON_MAX_CAVEATS 65536
/* Recommended secret length */
#define MACAROON_SUGGESTED_SECRET_LENGTH 32

/* Opaque type whose internals are private to libmacaroons */
struct macaroon;
struct macaroon_verifier;

enum macaroon_returncode
{
    MACAROON_SUCCESS          = 2048,
    MACAROON_OUT_OF_MEMORY    = 2049,
    MACAROON_HASH_FAILED      = 2050,
    MACAROON_INVALID          = 2051,
    MACAROON_TOO_MANY_CAVEATS = 2052,
    MACAROON_CYCLE            = 2053,
    MACAROON_BUF_TOO_SMALL    = 2054,
    MACAROON_NOT_AUTHORIZED   = 2055,
    MACAROON_NO_JSON_SUPPORT  = 2056
};

/* Create a new macaroon.
 *  - location/location_sz is a hint to the target's location
 *  - key/key_sz is the key used as a secret for macaroon construction
 *  - id/id_sz is the public identifier the macaroon issuer can use to identify
 *    the key
 */
struct macaroon*
macaroon_create(const unsigned char* location, size_t location_sz,
                const unsigned char* key, size_t key_sz,
                const unsigned char* id, size_t id_sz,
                enum macaroon_returncode* err);

/* Destroy a macaroon, freeing resources */
void
macaroon_destroy(struct macaroon* M);

/* Check a macaroon's integrity
 *
 * This routine is used internally, and is exposed as part of the public API for
 * use in assert() statements.
 *
 * 0 -> all good
 * !0 -> no good
 */
int
macaroon_validate(const struct macaroon* M);

/* Add a new first party caveat, and return a new macaroon.
 *  - predicate/predicate_sz is the caveat to be added to the macaroon
 *
 * Returns a new macaroon, leaving the original untouched.
 */
struct macaroon*
macaroon_add_first_party_caveat(const struct macaroon* M,
                                const unsigned char* predicate, size_t predicate_sz,
                                enum macaroon_returncode* err);

/* Add a new third party caveat, and return a new macaroon.
 *  - location/location_sz is a hint to the third party's location
 *  - key/keys_sz is a secret shared shared between this macaroon and the third
 *    party.  Guard it as carefully as you do the key for macaroon_create.
 *  - id/id_sz is the identifier for this macaroon.  If presented to the third
 *    party, the third party must be able to recall the secret and predicate to
 *    check.
 *    A good way to generate this ID is to generate N random bytes as the key,
 *    and encrypt these bytes and the caveat.  Pass the bytes and N as the key,
 *    and pass the ciphertext as the ID.
 *
 * Returns a new macaroon, leaving the original untouched.
 */
struct macaroon*
macaroon_add_third_party_caveat(const struct macaroon* M,
                                const unsigned char* location, size_t location_sz,
                                const unsigned char* key, size_t key_sz,
                                const unsigned char* id, size_t id_sz,
                                enum macaroon_returncode* err);

/* Where are the third-parties that give discharge macaroons? */
unsigned
macaroon_num_third_party_caveats(const struct macaroon* M);

int
macaroon_third_party_caveat(const struct macaroon* M, unsigned which,
                            const unsigned char** location, size_t* location_sz,
                            const unsigned char** identifier, size_t* identifier_sz);

/* Prepare the macaroon for a request */
struct macaroon*
macaroon_prepare_for_request(const struct macaroon* M,
                             const struct macaroon* D,
                             enum macaroon_returncode* err);

/* Verification tool for verifying macaroons */
struct macaroon_verifier*
macaroon_verifier_create();

void
macaroon_verifier_destroy(struct macaroon_verifier* V);

int
macaroon_verifier_satisfy_exact(struct macaroon_verifier* V,
                                const unsigned char* predicate, size_t predicate_sz,
                                enum macaroon_returncode* err);

int
macaroon_verifier_satisfy_general(struct macaroon_verifier* V,
                                  int (*general_check)(void* f, const unsigned char* pred, size_t pred_sz),
                                  void* f, enum macaroon_returncode* err);

int
macaroon_verify(const struct macaroon_verifier* V,
                const struct macaroon* M,
                const unsigned char* key, size_t key_sz,
                struct macaroon** MS, size_t MS_sz,
                enum macaroon_returncode* err);

/* Access routines for the macaroon */
void
macaroon_location(const struct macaroon* M,
                  const unsigned char** location, size_t* location_sz);

void
macaroon_identifier(const struct macaroon* M,
                    const unsigned char** identifier, size_t* identifier_sz);

void
macaroon_signature(const struct macaroon* M,
                   const unsigned char** signature, size_t* signature_sz);

/* Serialize and deserialize macaroons */
size_t
macaroon_serialize_size_hint(const struct macaroon* M);

int
macaroon_serialize(const struct macaroon* M,
                   char* data, size_t data_sz,
                   enum macaroon_returncode* err);

size_t
macaroon_serialize_json_size_hint(const struct macaroon* M);

int
macaroon_serialize_json(const struct macaroon* M,
                        char* data, size_t data_sz,
                        enum macaroon_returncode* err);

struct macaroon*
macaroon_deserialize_json(const char* data, size_t data_sz,
                          enum macaroon_returncode* err);

struct macaroon*
macaroon_deserialize(const char* data, enum macaroon_returncode* err);

/* Human-readable representation *FOR DEBUGGING ONLY* */
size_t
macaroon_inspect_size_hint(const struct macaroon* M);

int
macaroon_inspect(const struct macaroon* M,
                 char* data, size_t data_sz,
                 enum macaroon_returncode* err);

/* Utilities for manipulating and comparing macaroons */

/* allocate a new copy of the macaroon */
struct macaroon*
macaroon_copy(const struct macaroon* M,
              enum macaroon_returncode* err);

/* 0 if equal; !0 if non-equal; no other comparison implied */
int
macaroon_cmp(const struct macaroon* M, const struct macaroon* N);

#ifdef __cplusplus
} /* extern "C" */
#endif /* __cplusplus */
#endif /* macaroons_h_ */
