# Copyright (c) 2014, Robert Escriva
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
AM_MAKEFLAGS = --no-print-directory
AM_CPPFLAGS = $(SODIUM_CFLAGS)
AM_CFLAGS   = -fvisibility=hidden $(SODIUM_CFLAGS) $(WANAL_CFLAGS)
AM_CXXFLAGS = -fvisibility=hidden -fvisibility-inlines-hidden $(SODIUM_CFLAGS) $(WANAL_CXXFLAGS)

AM_DISTCHECK_CONFIGURE_FLAGS = --enable-python-bindings
TESTS_ENVIRONMENT = . $(abs_top_srcdir)/test/env.sh "${abs_top_srcdir}" "${abs_top_builddir}" "${VERSION}";

pyx_verbose = $(pyx_verbose_$(V))
pyx_verbose_ = $(pyx_verbose_$(AM_DEFAULT_VERBOSITY))
pyx_verbose_0 = @echo "  PYX   " $@;

EXTRA_DIST  =
EXTRA_DIST += README
EXTRA_DIST += LICENSE

include_HEADERS = macaroons.h

noinst_HEADERS = base64.h constants.h custom-config.h packet.h port.h

lib_LTLIBRARIES = libmacaroons.la

libmacaroons_la_SOURCES = base64.c macaroons.c packet.c port.c
libmacaroons_la_LIBADD  =
libmacaroons_la_LIBADD += $(SODIUM_LIBS)
if ENABLE_JSON_SUPPORT
libmacaroons_la_LIBADD += $(JSON_LIBS)
endif
libmacaroons_la_LDFLAGS = -version-info 0:1:0

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libmacaroons.pc

##################################### Tests ####################################

EXTRA_DIST += test/env.sh
EXTRA_DIST += test/python-hmac-sanity-check
EXTRA_DIST += test/python-hmac-sanity-check.sh
EXTRA_DIST += test/readme.sh

TESTS  =
TESTS += test/python-hmac-sanity-check.sh
#TESTS += test/readme.sh

#################################### Python ####################################

pyexec_LTLIBRARIES =
if ENABLE_PYTHON_BINDINGS
pyexec_LTLIBRARIES += bindings/python/macaroons.la
endif

EXTRA_DIST += bindings/python/macaroons.pyx

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
bindings_python_macaroons_la_LDFLAGS = -module -avoid-version -export-symbols-regex initmacaroons $(AM_LDFLAGS) $(LDFLAGS)
bindings/python/macaroons.c: bindings/python/macaroons.pyx
	$(pyx_verbose)cython bindings/python/macaroons.pyx
