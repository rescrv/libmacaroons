#include "unity_fixture.h"

static void RunAllTests(void) {
    RUN_TEST_GROUP(SerializationTests);
    RUN_TEST_GROUP(VarintTests);
    RUN_TEST_GROUP(VerifierTests);
    RUN_TEST_GROUP(MacaroonBuilderTests);
    RUN_TEST_GROUP(PrepareVerifyTests);
}

int main(int argc, const char * argv[]) {
    UnityMain(argc, argv, RunAllTests);
}