//
// Created by Nicholas Robison on 2019-01-22.
//

/* C */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int main() {
#ifdef __AFL_HAVE_MANUAL_CONTROL
    while (__AFL_LOOP(1000)) {
#endif

    // Read from stdin
    char *line = NULL;
    size_t size = 0;

    ssize_t amt = getline(&line, &size, stdin);

    if (amt < 0) {
        fprintf(stderr, "could not read from stdin: %s\n", strerror(ferror(stdin)));
        return -1;
    }

    uint8_t *buffer = (u_int8_t *)line;

    LLVMFuzzerTestOneInput(buffer, size);

#ifdef __AFL_HAVE_MANUAL_CONTROL
    }
#endif
}