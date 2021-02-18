#include "unity_fixture.h"

static void RunAllTests(void) {
    RUN_TEST_GROUP(SerializationTests);
    RUN_TEST_GROUP(VarintTests);
}

int main(int argc, const char * argv[]) {
    UnityMain(argc, argv, RunAllTests);
}