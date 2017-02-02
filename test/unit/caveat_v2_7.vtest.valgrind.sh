#!/bin/sh
valgrind --tool=memcheck --trace-children=yes --error-exitcode=127 --leak-check=full --gen-suppressions=all --suppressions="${MACAROONS_SRCDIR}/macaroons.supp" "${MACAROONS_SRCDIR}/test/unit/caveat_v2_7.vtest.sh"
