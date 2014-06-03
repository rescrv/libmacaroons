// Copyright 2013 The Go-SQLite Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Adapted from github.com/mxk/go-sqlite/sqlite3/util.go by
// Casey Marshall <cmars@cmarstech.com>

package macaroons

import "C"

import (
	"reflect"
	"unsafe"
)

const nuls = "\x00"

// cStr returns a char* pointer to the first byte in s.
func cStr(s string) *C.char {
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return (*C.char)(unsafe.Pointer(h.Data))
}

// cUStrN returns an unsigned char* pointer to the first byte in s and the byte
// length of the string.
func cUStrN(s string) (*C.uchar, C.size_t) {
	h := (*reflect.StringHeader)(unsafe.Pointer(&s))
	return (*C.uchar)(unsafe.Pointer(h.Data)), C.size_t(len(s))
}

// cBytes returns a pointer to the first byte in b.
func cBytes(b []byte) *C.char {
	return (*C.char)(unsafe.Pointer((*reflect.SliceHeader)(unsafe.Pointer(&b)).Data))
}

// goUStrN returns a Go representation of an n-unsigned byte C string.
func goStrN(p *C.uchar, n C.size_t) (s string) {
	if n > 0 {
		h := (*reflect.StringHeader)(unsafe.Pointer(&s))
		h.Data = uintptr(unsafe.Pointer(p))
		h.Len = int(n)
	}
	return
}
