//
// Created by Nick Robison on 2/19/21.
//

/* c */
#include <string.h>

/* macaroons */
#include <libmacaroons/macaroons.h>

/* unity */
#include "unity.h"
#include "unity_fixture.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wpointer-sign"
TEST_GROUP(MacaroonBuilderTests);


TEST_SETUP(MacaroonBuilderTests) {

}

TEST_TEAR_DOWN(MacaroonBuilderTests) {

}

TEST(MacaroonBuilderTests, location_doesnt_change_signature) {
    const char* id = "we used our secret key";
    const char* secret = "this is our super secret key; only we should know it";

    enum macaroon_returncode err = MACAROON_SUCCESS;

    const char* loc1 = "http://location_ONE";
    const struct macaroon* M1 = macaroon_create(loc1, strlen(loc1), secret, strlen(secret), id, strlen(id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    const char* loc2 = "http://location_TWO";
    const struct macaroon* M2 = macaroon_create(loc2, strlen(loc2), secret, strlen(secret), id, strlen(id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    const unsigned char* sig1;
    size_t sig1_sz = 0;
    macaroon_signature(M1, &sig1, &sig1_sz);
    const unsigned char* sig2;
    size_t sig2_sz = 0;
    macaroon_signature(M2, &sig2, &sig2_sz);

    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(sig1, sig2, sig1_sz, "Signatures should be equal");
}

TEST(MacaroonBuilderTests, add_third_party_caveat) {
    const char* id = "we used our other secret key";
    const char* secret = "this is a different super-secret key; never use the same secret twice";

    enum macaroon_returncode err = MACAROON_SUCCESS;
    const char* location = "http://mybank/";
    struct macaroon* M = macaroon_create(location, strlen(location), secret, strlen(secret), id, strlen(id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    const char* predicate = "account = 3735928559";
    struct macaroon* M2 = macaroon_add_first_party_caveat(M, predicate, strlen(predicate), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
    macaroon_destroy(M);

    const char* cav_key = "4; guaranteed random by a fair toss of the dice";
    const char* cav_id = "this was how we remind auth of key/pred";
    const char* cav_location = "http://auth.mybank/";
    struct macaroon* M3 = macaroon_add_third_party_caveat(M2, cav_location, strlen(cav_location), cav_key, strlen(cav_key), cav_id, strlen(cav_id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
    macaroon_destroy(M2);

    const unsigned char* new_loc;
    size_t new_loc_sz = 0;
    macaroon_location(M3, &new_loc, &new_loc_sz);
    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(location, new_loc, new_loc_sz, "Locations should match");

    const unsigned char* new_id;
    size_t  new_id_sz = 0;
    macaroon_identifier(M3, &new_id, &new_id_sz);
    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(id, new_id, new_id_sz, "IDs should match");
    TEST_ASSERT_EQUAL_INT_MESSAGE(2, macaroon_num_caveats(M3), "Should have 2 caveats");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, macaroon_num_first_party_caveats(M3), "Should have 1 first_party caveat");
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, macaroon_num_third_party_caveats(M3), "Should have 1 third_party caveat");

    // Serialize and verify
    const char *ser_verify = "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMmNpZGVudGlmaWVyIHdlIHVzZWQgb3VyIG90aGVyIHNlY3JldCBrZXkKMDAxZGNpZCBhY2NvdW50ID0gMzczNTkyODU1OQowMDMwY2lkIHRoaXMgd2FzIGhvdyB3ZSByZW1pbmQgYXV0aCBvZiBrZXkvcHJlZAowMDUxdmlkI";

    size_t ser_sz = macaroon_serialize_size_hint(M3, MACAROON_V1);
    unsigned char* serialized = malloc(ser_sz);
    macaroon_serialize(M3, MACAROON_V1, serialized, ser_sz, &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
    TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(ser_verify, serialized, strlen(ser_verify), "Serialized prefixes should match");
}

TEST(MacaroonBuilderTests, add_third_party_caveat_encoded) {
    const char* id = "we used our other secret key";
    const char* secret = "this is a different super-secret key; never use the same secret twice";

    enum macaroon_returncode err = MACAROON_SUCCESS;
    const char* location = "http://mybank/";
    struct macaroon* M = macaroon_create(location, strlen(location), secret, strlen(secret), id, strlen(id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    const char* predicate = "user = Alice";
    struct macaroon* M2 = macaroon_add_first_party_caveat(M, predicate, strlen(predicate), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
    macaroon_destroy(M);

    const char* cav_key = "4; guaranteed random by a fair toss of the dice";
    const char* cav_id = "³\\u0016^Ü\\u0091\\u0007\\u0007'Võ\\u0016Ü\\u009F\\u0090tÄrrª\\u0088í9@é? ºrd\\u0018x÷";
    const char* cav_location = "http://auth.mybank/";
    struct macaroon* M3 = macaroon_add_third_party_caveat(M2, cav_location, strlen(cav_location), cav_key, strlen(cav_key), cav_id, strlen(cav_id), &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(1, macaroon_num_third_party_caveats(M3), "Should have a third party caveat");
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
    macaroon_destroy(M2);

    struct macaroon* D = macaroon_create(cav_location, strlen(cav_location), cav_key, strlen(cav_key), cav_id, strlen(cav_id), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    struct macaroon* DP = macaroon_prepare_for_request(M, D, &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);
//    macaroon_destroy(D);

    struct macaroon_verifier* V = macaroon_verifier_create();
    macaroon_verifier_satisfy_exact(V, predicate, strlen(predicate), &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    struct macaroon** discharges = malloc(sizeof(struct macaroon*) * 1);
    discharges[0] = DP;

    macaroon_verify(V, M3, secret, strlen(secret), discharges, 1, &err);
    TEST_ASSERT_EQUAL(MACAROON_SUCCESS, err);

    macaroon_verify(V, M3, secret, strlen(secret), NULL, 0, &err);
    TEST_ASSERT_EQUAL(MACAROON_NOT_AUTHORIZED, err);
    macaroon_verifier_destroy(V);
    macaroon_destroy(M3);
    macaroon_destroy(DP);

}

TEST_GROUP_RUNNER(MacaroonBuilderTests) {
    RUN_TEST_CASE(MacaroonBuilderTests, location_doesnt_change_signature);
    RUN_TEST_CASE(MacaroonBuilderTests, add_third_party_caveat);
    RUN_TEST_CASE(MacaroonBuilderTests, add_third_party_caveat_encoded);
}
#pragma clang diagnostic pop