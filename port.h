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

#ifndef macaroons_port_h_
#define macaroons_port_h_

#define MACAROON_HASH_BYTES 32U

#define MACAROON_SECRET_KEY_BYTES 32U
#define MACAROON_SECRET_NONCE_BYTES 24U

/*
 * The number of zero bytes required by crypto_secretbox
 * before the plaintext.
 */
#define MACAROON_SECRET_TEXT_ZERO_BYTES 32U

/*
 * The number of zero bytes placed by crypto_secretbox
 * before the ciphertext
 */
#define MACAROON_SECRET_BOX_ZERO_BYTES 16U

void
macaroon_memzero(void* data, size_t data_sz);

int
macaroon_memcmp(const void* data1, const void* data2, size_t data_sz);

int
macaroon_randombytes(void* data, const size_t data_sz);

int
macaroon_hmac(const unsigned char* key, size_t key_sz,
              const unsigned char* text, size_t text_sz,
              unsigned char* hash);

int
macaroon_secretbox(const unsigned char* enc_key,
                   const unsigned char* enc_nonce,
                   const unsigned char* plaintext, size_t plaintext_sz,
                   unsigned char* ciphertext);

int
macaroon_secretbox_open(const unsigned char* enc_key,
                        const unsigned char* enc_nonce,
                        const unsigned char* ciphertext, size_t ciphertext_sz,
                        unsigned char* plaintext);

void
macaroon_bin2hex(const unsigned char* bin, size_t bin_sz, char* hex);

int
macaroon_hex2bin(const char* hex, size_t hex_sz, unsigned char* bin);

#endif /* macaroons_port_h_ */
