/* Copyright (c) 2014, Casey Marshall
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
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

// Package macaroons implements a Go binding for libmacaroons.
//
// A pure Go package with equivalent (and compatible) functionality also
// exists. See http://godoc.org/gopkg.in/macaroon.v1.
package macaroons

/*
#cgo CFLAGS: -I../../..
#cgo LDFLAGS: -L../../../.libs -lmacaroons -lsodium
#include <stdio.h>
#include <stdlib.h>
#include "macaroons.h"
*/
import "C"

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"unsafe"
)

// macaroonError returns an error describing the macaroon return code.
func macaroonError(err C.enum_macaroon_returncode) error {
	switch err {
	case C.MACAROON_SUCCESS:
		return nil
	case C.MACAROON_OUT_OF_MEMORY:
		return fmt.Errorf("out of memory")
	case C.MACAROON_HASH_FAILED:
		return fmt.Errorf("hash failed")
	case C.MACAROON_INVALID:
		return fmt.Errorf("invalid")
	case C.MACAROON_TOO_MANY_CAVEATS:
		return fmt.Errorf("too many caveats")
	case C.MACAROON_CYCLE:
		return fmt.Errorf("cycle")
	case C.MACAROON_BUF_TOO_SMALL:
		return fmt.Errorf("buffer too small")
	case C.MACAROON_NOT_AUTHORIZED:
		return fmt.Errorf("not authorized")
	case C.MACAROON_NO_JSON_SUPPORT:
		return fmt.Errorf("no JSON support")
	}
	return fmt.Errorf("unknown error %d", err)
}

// Macaroon holds a macaroon.
// See Fig. 7 of http://theory.stanford.edu/~ataly/Papers/macaroons.pdf
// for a description of the data contained within.
// Macaroons are mutable objects - use Copy as appropriate
// to avoid unwanted mutation.
type Macaroon struct {
	m *C.struct_macaroon
}

type ThirdPartyId struct {
	Location, Id string
}

// NewMacaroon returns a new macaroon with the given location,
// root key and identifier.
func NewMacaroon(location, key, id string) (*Macaroon, error) {
	var err C.enum_macaroon_returncode
	cLoc, cLocSz := cUStrN(location)
	cKey, cKeySz := cUStrN(key)
	cId, cIdSz := cUStrN(id)
	m := C.macaroon_create(cLoc, cLocSz, cKey, cKeySz, cId, cIdSz, &err)
	if err != 0 {
		defer C.macaroon_destroy(m)
		return nil, macaroonError(err)
	}
	return &Macaroon{m}, nil
}

// Destroy frees the memory held by a macaroon.
func (m *Macaroon) Destroy() {
	C.macaroon_destroy(m.m)
	m.m = nil
}

// Validate does nothing.
func (m *Macaroon) Validate() error {
	rc := C.macaroon_validate(m.m)
	if rc != 0 {
		return fmt.Errorf("validation error: %d", rc)
	}
	return nil
}

func (m *Macaroon) newFirstPartyCaveat(predicate string) (*Macaroon, error) {
	var err C.enum_macaroon_returncode

	cPred, cPredSz := cUStrN(predicate)
	mPrime := C.macaroon_add_first_party_caveat(m.m, cPred, cPredSz, &err)
	if err != 0 {
		return nil, macaroonError(err)
	}
	return &Macaroon{mPrime}, nil
}

// WithFirstPartyCaveat adds a first party caveat with the given predicate
// to m.
func (m *Macaroon) WithFirstPartyCaveat(predicate string) error {
	mNext, err := m.newFirstPartyCaveat(predicate)
	if err != nil {
		return err
	}
	mPrev := m.m
	m.m = mNext.m
	C.macaroon_destroy(mPrev)
	return nil
}

func (m *Macaroon) newThirdPartyCaveat(location, key, id string) (*Macaroon, error) {
	var err C.enum_macaroon_returncode
	cLoc, cLocSz := cUStrN(location)
	cKey, cKeySz := cUStrN(key)
	cId, cIdSz := cUStrN(id)
	mNew := C.macaroon_add_third_party_caveat(m.m, cLoc, cLocSz, cKey, cKeySz, cId, cIdSz, &err)
	if err != 0 {
		return nil, macaroonError(err)
	}
	return &Macaroon{mNew}, nil
}

// WithThirdPartyCaveat adds a caveat with the given location,
// key and id to m.
func (m *Macaroon) WithThirdPartyCaveat(location, key, id string) error {
	mNext, err := m.newThirdPartyCaveat(location, key, id)
	if err != nil {
		return err
	}
	mPrev := m.m
	m.m = mNext.m
	C.macaroon_destroy(mPrev)
	return nil
}

// Marshal returns the macaroon marshaled as for
// m.MarshalBinary, but also encapsulated in URL-safe
// base64 with no padding.
func (m *Macaroon) Marshal() (string, error) {
	var err C.enum_macaroon_returncode

	n := C.macaroon_serialize_size_hint(m.m)
	buf := make([]byte, n)
	data := cBytes(buf)

	sz := C.macaroon_serialize(m.m, data, n, &err)
	if sz < 0 {
		return "", macaroonError(err)
	}
	buf = bytes.TrimRight(buf, nuls)
	return string(buf), nil
}

// Unmarshal unmarshals a macaroon in the format produced
// by Marshal. It also accepts base64-encoded JSON format.
func Unmarshal(s string) (*Macaroon, error) {
	var err C.enum_macaroon_returncode
	data := cStr(s)
	m := C.macaroon_deserialize(data, &err)
	if m == nil { // TODO: err gets set to INVALID even if this returns successful, fix that
		return nil, macaroonError(err)
	}
	return &Macaroon{m}, nil
}

// Location returns macaroon's location.
func (m *Macaroon) Location() string {
	var loc *C.uchar
	var locSz C.size_t
	C.macaroon_location(m.m, &loc, &locSz)
	return goStrN(loc, locSz)
}

// Id returns the macaroon's identifier.
func (m *Macaroon) Id() string {
	var id *C.uchar
	var idSz C.size_t
	C.macaroon_identifier(m.m, &id, &idSz)
	return goStrN(id, idSz)
}

// Signature returns the macaroon's signature.
// Note that the string is a binary bit string.
func (m *Macaroon) Signature() string {
	var sig *C.uchar
	var sigSz C.size_t
	C.macaroon_signature(m.m, &sig, &sigSz)
	return goStrN(sig, sigSz)
}

// Inspect returns the macaroon in "human readable"
// format.
func (m *Macaroon) Inspect() (string, error) {
	var err C.enum_macaroon_returncode
	n := C.macaroon_inspect_size_hint(m.m)
	buf := make([]byte, n)
	data := cBytes(buf)

	sz := C.macaroon_inspect(m.m, data, n, &err)
	if sz < 0 {
		return "", macaroonError(err)
	} else if sz < 0 {
		return "", fmt.Errorf("serialization error")
	}
	buf = bytes.TrimRight(buf, nuls)
	return string(buf), nil
}

// ThirdPartyCaveats returns all the third party caveats
// in m.
func (m *Macaroon) ThirdPartyCaveats() ([]ThirdPartyId, error) {
	var result []ThirdPartyId
	n := C.macaroon_num_third_party_caveats(m.m)
	for i := C.uint(0); i < n; i++ {
		var loc *C.uchar
		var locSz C.size_t
		var id *C.uchar
		var idSz C.size_t
		rc := C.macaroon_third_party_caveat(m.m, i, &loc, &locSz, &id, &idSz)
		if rc < 0 {
			return nil, fmt.Errorf("failed to read third-party caveat %d", i)
		}
		result = append(result, ThirdPartyId{
			Location: goStrN(loc, locSz),
			Id:       goStrN(id, idSz),
		})
	}
	return result, nil
}

// PrepareForRequest returns a copy of the given discharge macaroon
// bound to the primary macaroon m.
func (m *Macaroon) PrepareForRequest(discharge *Macaroon) (*Macaroon, error) {
	var err C.enum_macaroon_returncode
	prepared := C.macaroon_prepare_for_request(m.m, discharge.m, &err)
	if prepared == nil {
		return nil, macaroonError(err)
	}
	return &Macaroon{prepared}, nil
}

// Copy returns a copy of the macaroon.
func (m *Macaroon) Copy() (*Macaroon, error) {
	var err C.enum_macaroon_returncode
	newM := C.macaroon_copy(m.m, &err)
	if newM == nil {
		return nil, macaroonError(err)
	}
	return &Macaroon{newM}, nil
}

func cbuf(data []byte) *C.char {
	if len(data) == 0 {
		return nil
	}
	return (*C.char)(unsafe.Pointer(&data[0]))
}

// MarshalJSON marshals the macaroon to JSON format.
// It implements json.Marshaler.
func (m *Macaroon) MarshalJSON() ([]byte, error) {
	var merr C.enum_macaroon_returncode
	b64data := make([]byte, C.macaroon_serialize_json_size_hint(m.m))
	rc := C.macaroon_serialize_json(m.m, cbuf(b64data), C.size_t(len(b64data)), &merr)
	if rc < 0 {
		return nil, macaroonError(merr)
	}
	return base64Decode(b64data)
}

// UnmarshalJSON unmarshals the macaroon from JSON format.
// It implements json.Unmarshaler.
func (m *Macaroon) UnmarshalJSON(data []byte) error {
	var err C.enum_macaroon_returncode
	cm := C.macaroon_deserialize_json(cbuf(data), C.size_t(len(data)), &err)
	if cm == nil {
		return macaroonError(err)
	}
	m.m = cm
	return nil
}

// MarshalBinary marshals the macaroon into binary format.
// This is the same as Marshal but without the base64 encoding.
func (m *Macaroon) MarshalBinary() ([]byte, error) {
	var merr C.enum_macaroon_returncode
	b64data := make([]byte, C.macaroon_serialize_size_hint(m.m))
	rc := C.macaroon_serialize(m.m, cbuf(b64data), C.size_t(len(b64data)), &merr)
	if rc < 0 {
		return nil, macaroonError(merr)
	}
	return base64Decode(b64data)
}

// UnmarshalBinary unmarshals the macaroon from binary
// format.
func (m *Macaroon) UnmarshalBinary(data []byte) error {
	// libmacaroons expects the serialization in base64 encoding already,
	// but we just have the binary, so encode it for libmacaroons.
	b64data := make([]byte, base64.URLEncoding.EncodedLen(len(data)))
	base64.URLEncoding.Encode(b64data, data)
	var err C.enum_macaroon_returncode
	cm := C.macaroon_deserialize(cbuf(b64data), &err)
	if cm == nil {
		return macaroonError(err)
	}
	m.m = cm
	return nil
}

// Cmp returns 0 if the macaroons are equal, and
// non-zero otherwise.
func Cmp(a, b *Macaroon) int {
	if a == nil || a.m == nil || b == nil || b.m == nil {
		panic("compare nil macaroon")
	}
	return int(C.macaroon_cmp(a.m, b.m))
}

// base64Decode decodes base64 data that might be missing trailing
// pad characters.
func base64Decode(b64data []byte) ([]byte, error) {
	if i := bytes.IndexByte(b64data, 0); i >= 0 {
		b64data = b64data[0:i]
	}
	paddedLen := (len(b64data) + 3) / 4 * 4
	for i := len(b64data); i < paddedLen; i++ {
		b64data = append(b64data, '=')
	}
	data := make([]byte, base64.URLEncoding.DecodedLen(len(b64data)))
	n, err := base64.URLEncoding.Decode(data, b64data)
	if err != nil {
		return nil, fmt.Errorf("cannot decode base64 macaroon serialization: %v", b64data, err)
	}
	return data[0:n], nil
}
