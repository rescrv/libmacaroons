//
// Created by Nicholas Robison on 2019-01-22.
//

/* C */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* macaroons */
#include "macaroons.h"
#include "base64.h"

size_t
int2size_t(int val) {
    return (val < 0) ? __SIZE_MAX__ : (size_t) ((unsigned) val);
}

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {

    unsigned char *buf = malloc(size);
    int rc = b64_pton((const char *) data, buf, size);
    if (rc < 1) {
        free(buf);
        return 0;
    }

    enum macaroon_returncode err = MACAROON_SUCCESS;
    struct macaroon *M = macaroon_deserialize(buf, int2size_t(rc), &err);
    free(buf);
    free(M);
    return 0;
}