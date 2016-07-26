// This code is derived from code distributed as part of Google LevelDB.
// The original is available in leveldb as util/coding.h.
// This file was retrieved Jul 15, 2013 by Robert Escriva and imported into
// libe.  This code is copied/modified from libe.

// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.
//
// Endian-neutral encoding:
// * Fixed-length numbers are encoded with least-significant byte first
// * In addition we support variable length "varint" encoding
// * Strings are encoded prefixed by their length in varint format

#ifndef macaroons_varint_h_
#define macaroons_varint_h_

#define VARINT_MAX_SIZE 10

unsigned char*
packvarint(uint64_t value, unsigned char* ptr);

const unsigned char*
unpackvarint(const unsigned char* ptr,
             const unsigned char* end,
             uint64_t* value);

unsigned
varint_length(uint64_t v);

#endif /* macaroons_varint_h_ */
