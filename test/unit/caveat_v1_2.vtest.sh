#!/bin/sh
exec macaroon-test-verifier < "${MACAROONS_SRCDIR}/test/unit/caveat_v1_2.vtest"
