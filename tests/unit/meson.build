subproject('gtest')

gtest_dep = dependency('gtest')

ssha_test = executable('ssha_test',
    [
        'main.cpp',        
        'key/key_test.cpp',
        'key/key_manager_test.cpp',
        'key/pub_key_test.cpp',
        'extensions/session_bind_test.cpp',
        'extensions/restrict_destination_test.cpp',
        'utils/deserializer_test.cpp',
        'utils/serializer_test.cpp',
        'messages/message_test.cpp',
        'messages/sign_request_test.cpp',
        'messages/sign_response_test.cpp',
        'messages/add_identity_test.cpp',
        'messages/identities_answer_test.cpp',
        'messages/userauth_test.cpp',
        'messages/remove_identity_test.cpp',
        'messages/extension_test.cpp',
        'messages/lock_message_test.cpp'
    ],
    
    dependencies: [ssha, gtest_dep, botan],
    install: false
)

test('ssha unit tests', ssha_test)