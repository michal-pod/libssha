


add_executable(
        ssha_tests
        main.cpp
        key/key_test.cpp
        key/key_manager_test.cpp
        key/pub_key_test.cpp
        extensions/session_bind_test.cpp
        extensions/restrict_destination_test.cpp
        utils/deserializer_test.cpp
        utils/serializer_test.cpp
        messages/message_test.cpp
        messages/sign_request_test.cpp
        messages/sign_response_test.cpp
        messages/add_identity_test.cpp
        messages/identities_answer_test.cpp
        messages/userauth_test.cpp
        messages/remove_identity_test.cpp
        messages/extension_test.cpp
        messages/lock_message_test.cpp
)

target_link_libraries(
        ssha_tests
        GTest::gtest_main
        ssha
        ${BOTAN_LIBRARIES}
)
# Coverage flags are optional; they are enabled when building the ssha_coverage target
include(GoogleTest)
gtest_discover_tests(ssha_tests)    
