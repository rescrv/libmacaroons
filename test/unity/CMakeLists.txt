add_executable(unit_tests_app unit_tests.c test_helpers.c serialization_tests.c varint_tests.c verifier_tests.c macaroon_builder_tests.c request_verify_tests.c)
target_link_libraries(unit_tests_app unity macaroons)

add_test(unit_tests unit_tests_app)