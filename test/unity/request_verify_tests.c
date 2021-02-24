//
// Created by Nick Robison on 2/24/21.
//

/* c */
#include <string.h>

/* macaroons */
#include <libmacaroons/macaroons.h>
#include <libmacaroons/port.h>

/* unity */
#include "unity.h"
#include "unity_fixture.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"
TEST_GROUP(PrepareVerifyTests);

const char* id = "we used our secret key";
const char* secret = "this is our super secret key; only we should know it";
const char* location = "http://mybank/";
const char* loc2 = "http://auth.mybank/";
const char* cav_key = "4; guaranteed random by a fair toss of the dice";
const char* cav_id = "this was how we remind auth of key/pred";

struct macaroon* M;

TEST_SETUP(PrepareVerifyTests) {

    enum macaroon_returncode err = MACAROON_SUCCESS;
    struct macaroon* M1 = macaroon_create(location, strlen(location), secret, strlen(secret), id, strlen(id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    const char* cav = "account = 3735928559";
    struct macaroon* M2 = macaroon_add_first_party_caveat(M1, cav, strlen(cav), &err);
    macaroon_destroy(M1);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    M = macaroon_add_third_party_caveat(M2, loc2, strlen(loc2), cav_key, strlen(cav_key), cav_id, strlen(cav_id), &err);
    macaroon_destroy(M2);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
}

TEST_TEAR_DOWN(PrepareVerifyTests) {

}

TEST(PrepareVerifyTests, prepare_request_verify_test_simple) {
    enum macaroon_returncode err = MACAROON_SUCCESS;
    struct macaroon* M1 = macaroon_create(loc2, strlen(loc2), cav_key, strlen(cav_key), cav_id, strlen(cav_id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    const char* cav = "time < 2025-01-01T00:00";
    struct macaroon* D = macaroon_add_first_party_caveat(M1, cav, strlen(cav), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
    macaroon_destroy(M1);

    const unsigned char* sig;
    size_t sig_sz = 0;
    macaroon_signature(D, &sig, &sig_sz);
    char* hex = malloc(sizeof(char*) * sig_sz);
    macaroon_bin2hex(sig, sig_sz, hex);

    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE("b338d11fb136c4b95c86efe146f77978cd0947585375ba4d4da4ef68be2b3e8b", hex, sig_sz, "Signatures should be equal");
}

TEST(PrepareVerifyTests, prepare_request_verify_test_complex) {

}

TEST_GROUP_RUNNER(PrepareVerifyTests) {
    RUN_TEST_CASE(PrepareVerifyTests, prepare_request_verify_test_simple);
    RUN_TEST_CASE(PrepareVerifyTests, prepare_request_verify_test_complex);
}
#pragma clang diagnostic pop