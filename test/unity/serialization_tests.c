//
// Created by Nick Robison on 2/18/21.
//

#include "unity.h"
#include "unity_fixture.h"

struct macaroon *deserialize_macaroon(const char *serialized);

TEST_GROUP(SerializationTests);


TEST_SETUP(SerializationTests) {

}

TEST_TEAR_DOWN(SerializationTests) {

}

TEST(SerializationTests, test_serialization_1) {
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ESm1jMmxuYm1GMGRYSmxJUFZJQl9iY2J0LUl2dzl6QnJPQ0pXS2pZbE05djNNNXVtRjJYYVM5SloySENn"),
                                 "V1 should not be null");
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAAYgfN7nklEcW8b1KEhYBd_psk54XijiqZMB-dcRxgnjjvc="),
                                 "V2 should not be null");
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "eyJ2IjoyLCJsIjoiaHR0cDovL2V4YW1wbGUub3JnLyIsImkiOiJrZXlpZCIsImMiOltdLCJzNjQiOiJmTjdua2xFY1c4YjFLRWhZQmRfcHNrNTRYaWppcVpNQi1kY1J4Z25qanZjIn0="),
                                 "V2J should not be null");
}

TEST(SerializationTests, test_serialization_2) {
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ESm1jMmxuYm1GMGRYSmxJUFZJQl9iY2J0LUl2dzl6QnJPQ0pXS2pZbE05djNNNXVtRjJYYVM5SloySENn"),
                                 "V1 should not be null");
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQAABiD1SAf23G7fiL8PcwazgiVio2JTPb9zObphdl2kvSWdhw=="),
                                 "V2 should not be null");
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "eyJ2IjoyLCJsIjoiaHR0cDovL2V4YW1wbGUub3JnLyIsImkiOiJrZXlpZCIsImMiOlt7ImkiOiJhY2NvdW50ID0gMzczNTkyODU1OSJ9XSwiczY0IjoiOVVnSDl0eHUzNGlfRDNNR3M0SWxZcU5pVXoyX2N6bTZZWFpkcEwwbG5ZYyJ9"),
                                 "V2J should not be null");
}

TEST(SerializationTests, test_serialization_3) {
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "TURBeU1XeHZZMkYwYVc5dUlHaDBkSEE2THk5bGVHRnRjR3hsTG05eVp5OEtNREF4Tldsa1pXNTBhV1pwWlhJZ2EyVjVhV1FLTURBeFpHTnBaQ0JoWTJOdmRXNTBJRDBnTXpjek5Ua3lPRFUxT1Fvd01ERTFZMmxrSUhWelpYSWdQU0JoYkdsalpRb3dNREptYzJsbmJtRjBkWEpsSUV2cFo4MGVvTWF5YTY5cVNwVHVtd1d4V0liYUM2aGVqRUtwUEkwT0VsNzhDZw=="),
                                 "V1 should not be null");
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "AgETaHR0cDovL2V4YW1wbGUub3JnLwIFa2V5aWQAAhRhY2NvdW50ID0gMzczNTkyODU1OQACDHVzZXIgPSBhbGljZQAABiBL6WfNHqDGsmuvakqU7psFsViG2guoXoxCqTyNDhJe_A=="),
                                 "V2 should not be null");
    TEST_ASSERT_NOT_NULL_MESSAGE(deserialize_macaroon(
            "eyJ2IjoyLCJsIjoiaHR0cDovL2V4YW1wbGUub3JnLyIsImkiOiJrZXlpZCIsImMiOlt7ImkiOiJhY2NvdW50ID0gMzczNTkyODU1OSJ9LHsiaSI6InVzZXIgPSBhbGljZSJ9XSwiczY0IjoiUy1sbnpSNmd4ckpycjJwS2xPNmJCYkZZaHRvTHFGNk1RcWs4alE0U1h2dyJ9"),
                                 "V2J should not be null");
}

TEST_GROUP_RUNNER(SerializationTests) {
    RUN_TEST_CASE(SerializationTests, test_serialization_1);
    RUN_TEST_CASE(SerializationTests, test_serialization_2);
    RUN_TEST_CASE(SerializationTests, test_serialization_3);
}