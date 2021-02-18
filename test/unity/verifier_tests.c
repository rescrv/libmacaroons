//
// Created by Nick Robison on 2/18/21.
//
/* C */
#include <stdbool.h>

/* unity */
#include "unity_fixture.h"

struct verifier_test {
    int version;
    bool authorized;
    const char *serialized;
    const char *key;
    size_t num_caveats;
    const char **caveats;
};

void verify_macaroon(const struct verifier_test* test);


TEST_GROUP(VerifierTests);

TEST_SETUP(VerifierTests) {

}

TEST_TEAR_DOWN(VerifierTests) {

}

TEST(VerifierTests, root_v1_1) {
    struct verifier_test t = {
            .version = 1,
            .authorized = true,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeVpuTnBaMjVoZEhWeVpTQjgzdWVTVVJ4Ynh2VW9TRmdGMy1teVRuaGVLT0twa3dINTF4SEdDZU9POXdv"
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, root_v1_2) {
    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is not the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeVpuTnBaMjVoZEhWeVpTQjgzdWVTVVJ4Ynh2VW9TRmdGMy1teVRuaGVLT0twa3dINTF4SEdDZU9POXdv"
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, root_v2_1) {
    struct verifier_test t = {
            .version = 1,
            .authorized = true,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAAYgfN7nklEcW8b1KEhYBd_psk54XijiqZMB-dcRxgnjjvc"
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, root_v2_2) {
    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is not the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAAYgfN7nklEcW8b1KEhYBd_psk54XijiqZMB-dcRxgnjjvc"
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v1_1) {
    const char *caveats[1] = {"account = 3735928559"};

    const char **c = (const char**)(malloc(1 * sizeof(char*)));

    c[0] = caveats[0];

    struct verifier_test t = {
            .version = 1,
            .authorized = true,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeVpuTnBaMjVoZEhWeVpTQjgzdWVTVVJ4Ynh2VW9TRmdGMy1teVRuaGVLT0twa3dINTF4SEdDZU9POXdv",
            .num_caveats = 1,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v1_2) {
    const char *caveats[1] = {"account = 0000000000"};

    const char **c = (const char**)(malloc(1 * sizeof(char*)));

    c[0] = caveats[0];

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ESm1jMmxuYm1GMGRYSmxJUFZJQl9iY2J0LUl2dzl6QnJPQ0pXS2pZbE05djNNNXVtRjJYYVM5SloySENn",
            .num_caveats = 1,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v1_3) {
    const char *caveats[1] = {"account = 0000000000"};

    const char **c = (const char**)(malloc(1 * sizeof(char*)));

    c[0] = caveats[0];

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ESm1jMmxuYm1GMGRYSmxJUFZJQl9iY2J0LUl2dzl6QnJPQ0pXS2pZbE05djNNNXVtRjJYYVM5SloySENn",
            .num_caveats = 0,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v1_4) {
    static const size_t num_caveats = 2;
    const char *caveats[2] = {
            "account = 3735928559",
            "user = alice"
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = true,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ESm1jMmxuYm1GMGRYSmxJUFZJQl9iY2J0LUl2dzl6QnJPQ0pXS2pZbE05djNNNXVtRjJYYVM5SloySENn",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v1_5) {
    static const size_t num_caveats = 1;
    const char *caveats[1] = {
            "account = 3735928559",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ERTFZMmxrSUhWelpYSWdQU0JoYkdsalpRb3dNREptYzJsbmJtRjBkWEpsSUV2cFo4MGVvTWF5YTY5cVNwVHVtd1d4V0liYUM2aGVqRUtwUEkwT0VsNzhDZw",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v1_6) {
    static const size_t num_caveats = 1;
    const char *caveats[1] = {
            "user = alice",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ERTFZMmxrSUhWelpYSWdQU0JoYkdsalpRb3dNREptYzJsbmJtRjBkWEpsSUV2cFo4MGVvTWF5YTY5cVNwVHVtd1d4V0liYUM2aGVqRUtwUEkwT0VsNzhDZw==",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v2_1) {
    static const size_t num_caveats = 1;
    const char *caveats[1] = {
            "account = 3735928559",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = true,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQAABiD1SAf23G7fiL8PcwazgiVio2JTPb9zObphdl2kvSWdhw",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v2_2) {
    static const size_t num_caveats = 1;
    const char *caveats[1] = {
            "account = 0000000000",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQAABiD1SAf23G7fiL8PcwazgiVio2JTPb9zObphdl2kvSWdhw",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v2_3) {

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQAABiD1SAf23G7fiL8PcwazgiVio2JTPb9zObphdl2kvSWdhw",
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v2_4) {
    static const size_t num_caveats = 2;
    const char *caveats[2] = {
            "account = 3735928559",
            "user = alice",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = true,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v2_5) {
    static const size_t num_caveats = 1;
    const char *caveats[1] = {
            "account = 3735928559",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST(VerifierTests, caveat_v2_6) {
    static const size_t num_caveats = 1;
    const char *caveats[1] = {
            "user = alice",
    };
    const char **c = (const char**)(malloc(num_caveats * sizeof(char*)));

    for (size_t i = 0; i < num_caveats; i++) {
        c[i] = caveats[i];
    }

    struct verifier_test t = {
            .version = 1,
            .authorized = false,
            .key = "this is the key",
            .serialized = "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A",
            .num_caveats = num_caveats,
            .caveats = c
    };
    verify_macaroon(&t);
}

TEST_GROUP_RUNNER(VerifierTests) {
    RUN_TEST_CASE(VerifierTests, root_v1_1);
    RUN_TEST_CASE(VerifierTests, root_v1_2);
    RUN_TEST_CASE(VerifierTests, root_v2_1);
    RUN_TEST_CASE(VerifierTests, root_v2_2);

    RUN_TEST_CASE(VerifierTests, caveat_v1_1);
    RUN_TEST_CASE(VerifierTests, caveat_v1_2);
    RUN_TEST_CASE(VerifierTests, caveat_v1_3);
    RUN_TEST_CASE(VerifierTests, caveat_v1_4);
    RUN_TEST_CASE(VerifierTests, caveat_v1_5);
    RUN_TEST_CASE(VerifierTests, caveat_v1_6);

    RUN_TEST_CASE(VerifierTests, caveat_v2_1);
    RUN_TEST_CASE(VerifierTests, caveat_v2_2);
    RUN_TEST_CASE(VerifierTests, caveat_v2_3);
    RUN_TEST_CASE(VerifierTests, caveat_v2_4);
    RUN_TEST_CASE(VerifierTests, caveat_v2_5);
    RUN_TEST_CASE(VerifierTests, caveat_v2_6);
}