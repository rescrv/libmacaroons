# Copyright (c) 2014-2016, Robert Escriva
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of this project nor the names of its contributors may
#       be used to endorse or promote products derived from this software
#       without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CFLAGS   = -fvisibility=hidden $(WANAL_CFLAGS)
AM_CXXFLAGS = -fvisibility=hidden -fvisibility-inlines-hidden $(WANAL_CXXFLAGS)
if MAKE_NO_PRINT_DIRECTORY
AM_MAKEFLAGS = --no-print-directory
endif

AM_DISTCHECK_CONFIGURE_FLAGS = --enable-python-bindings PYTHON=python2
TESTS_ENVIRONMENT = . $(abs_top_srcdir)/test/env.sh "${abs_top_srcdir}" "${abs_top_builddir}" "${VERSION}";

pyx_verbose = $(pyx_verbose_$(V))
pyx_verbose_ = $(pyx_verbose_$(AM_DEFAULT_VERBOSITY))
pyx_verbose_0 = @echo "  PYX     " $@;

EXTRA_DIST  =
EXTRA_DIST += README
EXTRA_DIST += CAVEATS
EXTRA_DIST += LICENSE
EXTRA_DIST += doc/format.txt
EXTRA_DIST += doc/tests.txt

include_HEADERS = macaroons.h

noinst_HEADERS =
noinst_HEADERS += base64.h
noinst_HEADERS += constants.h
noinst_HEADERS += custom-config.h
noinst_HEADERS += macaroons-inner.h
noinst_HEADERS += packet.h
noinst_HEADERS += port.h
noinst_HEADERS += sha256.h
noinst_HEADERS += slice.h
noinst_HEADERS += sysendian.h
noinst_HEADERS += tweetnacl.h
noinst_HEADERS += varint.h
noinst_HEADERS += v1.h
noinst_HEADERS += v2.h

lib_LTLIBRARIES = libmacaroons.la

libmacaroons_la_SOURCES =
libmacaroons_la_SOURCES += base64.c
libmacaroons_la_SOURCES += macaroons.c
libmacaroons_la_SOURCES += packet.c
libmacaroons_la_SOURCES += slice.c
libmacaroons_la_SOURCES += port.c
libmacaroons_la_SOURCES += v1.c
libmacaroons_la_SOURCES += v2.c
libmacaroons_la_SOURCES += varint.c
libmacaroons_la_SOURCES += explicit_bzero.c
libmacaroons_la_SOURCES += timingsafe_bcmp.c
libmacaroons_la_SOURCES += tweetnacl.c
libmacaroons_la_SOURCES += sha256.c
libmacaroons_la_LIBADD = ${BSDLIBS}
libmacaroons_la_LDFLAGS = -version-info 0:1:0

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmacaroons.pc

##################################### Tests ####################################

EXTRA_DIST += test/env.sh
EXTRA_DIST += test/python-hmac-sanity-check
EXTRA_DIST += test/python-hmac-sanity-check.sh
EXTRA_DIST += test/readme.sh
EXTRA_DIST += macaroons.supp

check_SCRIPTS =
check_LTLIBRARIES = libmacaroons-shim.la
check_PROGRAMS =
check_PROGRAMS += test/varint
check_PROGRAMS += macaroon-test-verifier
check_PROGRAMS += macaroon-test-serialization

libmacaroons_shim_la_SOURCES = shim.c explicit_bzero.c
libmacaroons_shim_la_LDFLAGS = -module -avoid-version -rpath /evil/libtool/hack/to/force/shared/lib/creation

TESTS  =
if ENABLE_PYTHON_BINDINGS
TESTS += test/python-hmac-sanity-check.sh
TESTS += test/readme.sh
endif
TESTS += test/varint

test_varint_SOURCES = test/varint.c varint.c
test_varint_CFLAGS = $(AM_CFLAGS) $(CFLAGS)

macaroon_test_verifier_SOURCES = macaroon-test-verifier.c base64.c
macaroon_test_verifier_LDADD = libmacaroons.la
macaroon_test_verifier_CFLAGS = $(AM_CFLAGS) $(CFLAGS)

macaroon_test_serialization_SOURCES = macaroon-test-serialization.c base64.c
macaroon_test_serialization_LDADD = libmacaroons.la
macaroon_test_serialization_CFLAGS = $(AM_CFLAGS) $(CFLAGS)

macaroon_unit_test_stubs =
macaroon_unit_test_stubs += test/unit/caveat_v1_1.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v1_2.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v1_3.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v1_4.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v1_5.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v1_6.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v2_1.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v2_2.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v2_3.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v2_4.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v2_5.vtest.sh
macaroon_unit_test_stubs += test/unit/caveat_v2_6.vtest.sh
macaroon_unit_test_stubs += test/unit/root_v1_1.vtest.sh
macaroon_unit_test_stubs += test/unit/root_v1_2.vtest.sh
macaroon_unit_test_stubs += test/unit/root_v2_1.vtest.sh
macaroon_unit_test_stubs += test/unit/root_v2_2.vtest.sh
macaroon_unit_test_stubs += test/unit/serialization_1.sh
macaroon_unit_test_stubs += test/unit/serialization_2.sh
macaroon_unit_test_stubs += test/unit/serialization_3.sh

TESTS += $(macaroon_unit_test_stubs)
check_SCRIPTS += $(macaroon_unit_test_stubs)
EXTRA_DIST += $(macaroon_unit_test_stubs)
EXTRA_DIST += test/unit/caveat_v1_1.vtest
EXTRA_DIST += test/unit/caveat_v1_2.vtest
EXTRA_DIST += test/unit/caveat_v1_3.vtest
EXTRA_DIST += test/unit/caveat_v1_4.vtest
EXTRA_DIST += test/unit/caveat_v1_5.vtest
EXTRA_DIST += test/unit/caveat_v1_6.vtest
EXTRA_DIST += test/unit/caveat_v2_1.vtest
EXTRA_DIST += test/unit/caveat_v2_2.vtest
EXTRA_DIST += test/unit/caveat_v2_3.vtest
EXTRA_DIST += test/unit/caveat_v2_4.vtest
EXTRA_DIST += test/unit/caveat_v2_5.vtest
EXTRA_DIST += test/unit/caveat_v2_6.vtest
EXTRA_DIST += test/unit/root_v1_1.vtest
EXTRA_DIST += test/unit/root_v1_2.vtest
EXTRA_DIST += test/unit/root_v2_1.vtest
EXTRA_DIST += test/unit/root_v2_2.vtest
EXTRA_DIST += test/unit/serialization_1
EXTRA_DIST += test/unit/serialization_2
EXTRA_DIST += test/unit/serialization_3

#################################### Python ####################################

pyexec_LTLIBRARIES =
if ENABLE_PYTHON_BINDINGS
pyexec_LTLIBRARIES += bindings/python/macaroons.la
TESTS += test/issue_48.sh
endif

EXTRA_DIST += bindings/python/macaroons.pyx
EXTRA_DIST += test/issue_48
EXTRA_DIST += test/issue_48.sh

bindings_python_macaroons_la_SOURCES = bindings/python/macaroons.c
bindings_python_macaroons_la_CPPFLAGS =
bindings_python_macaroons_la_CPPFLAGS += $(PYTHON_CPPFLAGS)
bindings_python_macaroons_la_CPPFLAGS += $(AM_CPPFLAGS)
bindings_python_macaroons_la_CPPFLAGS += $(CPPFLAGS)
bindings_python_macaroons_la_CFLAGS =
bindings_python_macaroons_la_CFLAGS += -fvisibility=default
bindings_python_macaroons_la_CFLAGS += -fno-strict-aliasing
bindings_python_macaroons_la_CFLAGS += $(CFLAGS)
bindings_python_macaroons_la_LIBADD =
bindings_python_macaroons_la_LIBADD += libmacaroons.la
bindings_python_macaroons_la_LIBADD += $(PYTHON_LDFLAGS)
bindings_python_macaroons_la_LDFLAGS = -module -avoid-version -export-symbols-regex $(PYTHON_SYMBOL)macaroons $(AM_LDFLAGS) $(LDFLAGS)
bindings/python/macaroons.c: bindings/python/macaroons.pyx
	$(pyx_verbose)cython bindings/python/macaroons.pyx

################################################################################
################################## Maintenance #################################
################################################################################

EXTRA_DIST += maint/generate-shell-stubs

maintainer-generate:
	maint/generate-shell-stubs
	maint/valgrind-stubs
