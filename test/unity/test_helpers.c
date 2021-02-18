//
// Created by Nicholas Robison on 1/9/20.
//

/* C */
#include <stdlib.h>
#include <string.h>

/* macaroons */
#include <libmacaroons/macaroons.h>
#include <libmacaroons/base64.h>
#include <unity.h>

size_t
int2size_t(int val) {
    return (val < 0) ? __SIZE_MAX__ : (size_t) ((unsigned) val);
}

struct parsed_macaroon {
    unsigned char *B;
    struct macaroon *M;
    enum macaroon_format F;
};

struct macaroon *deserialize_macaroon(const char *serialized) {
    size_t buf_sz = strlen(serialized + 1);
    unsigned char *buf = malloc(buf_sz);

    memset(buf, 0, sizeof(*buf));
    int rc = b64_pton(serialized, buf, buf_sz);

    enum macaroon_returncode err;
    struct macaroon *M = macaroon_deserialize(buf, int2size_t(rc), &err);
    TEST_ASSERT_EQUAL_INT_MESSAGE(MACAROON_SUCCESS, err, "Should have successfully deserialized");
    return M;
}
