//
// Created by Nick Robison on 2/18/21.
//

/* C */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* macaroons */
#include "libmacaroons/varint.h"

/* unity */
#include "unity.h"
#include "unity_fixture.h"

void
varint_verify(uint64_t value, const char *representation) {
    const unsigned sz = strlen(representation);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, sz % 2, "Size should be multiple of 2");
    unsigned char buf[VARINT_MAX_SIZE];
    uint64_t eulav;
    unsigned int i;

    TEST_ASSERT_EQUAL_CHAR_MESSAGE(packvarint(value, buf), buf + sz / 2, "Should equal packed varint");
    TEST_ASSERT_EQUAL_CHAR_MESSAGE(unpackvarint(buf, buf + VARINT_MAX_SIZE, &eulav), buf + sz / 2,
                                   "Should equal unpacked varint");
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(value, eulav, "Packed/Unpacked value should be the same");
    assert(value == eulav);

    for (i = 0; i < sz / 2; ++i) {
        char hex[3];
        snprintf(hex, 3, "%02x", buf[i] & 0xff);
        TEST_ASSERT_EQUAL(representation[2 * i], hex[0]);
        TEST_ASSERT_EQUAL(representation[2 * i + 1], hex[1]);
    }
}

TEST_GROUP(VarintTests);

TEST_SETUP(VarintTests) {

}

TEST_TEAR_DOWN(VarintTests) {

}

TEST(VarintTests, test_varints) {
    varint_verify(0ULL, "00");
    varint_verify(5ULL, "05");
    varint_verify(127ULL, "7f");
    varint_verify(128ULL, "8001");
    varint_verify(16383ULL, "ff7f");
    varint_verify(16384ULL, "808001");
    varint_verify(16385ULL, "818001");
    varint_verify(16386ULL, "828001");
    varint_verify(16387ULL, "838001");
    varint_verify(16388ULL, "848001");
    varint_verify(3735928559ULL, "effdb6f50d");
    varint_verify(18446744073709551615ULL, "ffffffffffffffffff01");
}

TEST_GROUP_RUNNER(VarintTests) {
    RUN_TEST_CASE(VarintTests, test_varints);
}