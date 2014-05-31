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

package macaroons

/*
#cgo CFLAGS: -I../../..
#cgo LDFLAGS: -L../../../.libs -lmacaroons -lsodium
#include <stdio.h>
#include <stdlib.h>
#include "macaroons.h"
#include "wrapper.h"


*/
import "C"

import (
	"fmt"
	"reflect"
	"unsafe"
)

type Verifier struct {
	v         *C.struct_macaroon_verifier
	callbacks []GeneralCaveat
}

func NewVerifier() *Verifier {
	return &Verifier{v: C.macaroon_verifier_create()}
}

func (v *Verifier) Destroy() {
	C.macaroon_verifier_destroy(v.v)
}

func (v *Verifier) SatisfyExact(predicate string) error {
	var err C.enum_macaroon_returncode
	pred, predSz := cUStrN(predicate)
	rc := C.macaroon_verifier_satisfy_exact(v.v, pred, predSz, &err)
	if rc < 0 {
		return macaroonError(err)
	}
	return nil
}

type GeneralCaveat func(s string) bool

//export goGeneralCheck
func goGeneralCheck(f unsafe.Pointer, pred *C.uchar, predSz C.size_t) C.int {
	caveat := (*GeneralCaveat)(unsafe.Pointer(f))
	if (*caveat)(goStrN(pred, predSz)) {
		return 0
	}
	return -1
}

func (v *Verifier) SatisfyGeneral(caveat GeneralCaveat) error {
	var err C.enum_macaroon_returncode
	v.callbacks = append(v.callbacks, caveat)
	rc := C.macaroon_verifier_satisfy_general(v.v, (*[0]byte)(C.cGeneralCheck) /*(*[0]byte)(unsafe.Pointer(&generalCheckFn))*/, unsafe.Pointer(&caveat), &err)
	if rc < 0 {
		return macaroonError(err)
	}
	return nil
}

func (v *Verifier) Verify(m *Macaroon, key string, discharges ...*Macaroon) error {
	var err C.enum_macaroon_returncode
	msLen := C.size_t(len(discharges))
	ms := make([]*C.struct_macaroon, msLen)
	for i := range discharges {
		ms[i] = discharges[i].m
	}
	msPtr := (**C.struct_macaroon)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&ms)).Data))
	keyPtr, keySz := cUStrN(key)
	rc := C.macaroon_verify(v.v, m.m, keyPtr, keySz, msPtr, msLen, &err)
	if rc == 0 {
		return nil
	}
	if err != 0 {
		return macaroonError(err)
	}
	return fmt.Errorf("verify error: %d", rc)
}
