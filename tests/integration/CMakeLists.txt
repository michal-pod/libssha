file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/user_keys)

function(create_ssh_key key_type key_bits key_name key_output)
    add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/${key_output}/${key_name} ${CMAKE_CURRENT_BINARY_DIR}/${key_output}/${key_name}.pub
        COMMAND ${CMAKE_COMMAND} -E remove -f ${CMAKE_CURRENT_BINARY_DIR}/${key_output}/${key_name} ${CMAKE_CURRENT_BINARY_DIR}/${key_output}/${key_name}.pub
        COMMAND ssh-keygen -t ${key_type} -b ${key_bits} -f ${CMAKE_CURRENT_BINARY_DIR}/${key_output}/${key_name} -N '' -C "${key_name}_key" -q
        BYPRODUCTS ${CMAKE_CURRENT_BINARY_DIR}/${key_output}/${key_name}
        COMMENT "Generating test ${key_name} key pair in ${key_output} directory"
    )    
endfunction()

# create user keys for testing
create_ssh_key(rsa 2048 test_rsa user_keys)
create_ssh_key(ecdsa 256 test_ecdsa256 user_keys)
create_ssh_key(ecdsa 384 test_ecdsa384 user_keys)
create_ssh_key(ecdsa 521 test_ecdsa521 user_keys)
create_ssh_key(ed25519 255 test_ed25519 user_keys)

# create host_a keys for testing
create_ssh_key(rsa 2048 host_rsa host_a)
create_ssh_key(ecdsa 256 host_ecdsa256 host_a)
create_ssh_key(ecdsa 384 host_ecdsa384 host_a)
create_ssh_key(ecdsa 521 host_ecdsa521 host_a)
create_ssh_key(ed25519 255 host_ed25519 host_a)

# create host_b keys for testing
create_ssh_key(rsa 2048 host_rsa host_b)
create_ssh_key(ecdsa 256 host_ecdsa256 host_b)
create_ssh_key(ecdsa 384 host_ecdsa384 host_b)
create_ssh_key(ecdsa 521 host_ecdsa521 host_b)
create_ssh_key(ed25519 255 host_ed25519 host_b)

# create host_c keys for testing
create_ssh_key(rsa 2048 host_rsa host_c)
create_ssh_key(ecdsa 256 host_ecdsa256 host_c)
create_ssh_key(ecdsa 384 host_ecdsa384 host_c)
create_ssh_key(ecdsa 521 host_ecdsa521 host_c)
create_ssh_key(ed25519 255 host_ed25519 host_c)

function(generate_host_config SSH_PORT HOST_NAME OUTPUT_FILE)
add_custom_target(host_${HOST_NAME}_keys ALL DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/${HOST_NAME}/host_rsa
    ${CMAKE_CURRENT_BINARY_DIR}/${HOST_NAME}/host_ecdsa256
    ${CMAKE_CURRENT_BINARY_DIR}/${HOST_NAME}/host_ecdsa384
    ${CMAKE_CURRENT_BINARY_DIR}/${HOST_NAME}/host_ecdsa521
    ${CMAKE_CURRENT_BINARY_DIR}/${HOST_NAME}/host_ed25519
)
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/sshd_config.cmake ${OUTPUT_FILE})
endfunction(generate_host_config)

generate_host_config(2222 host_a ${CMAKE_CURRENT_BINARY_DIR}/host_a/sshd_config)

generate_host_config(2223 host_b ${CMAKE_CURRENT_BINARY_DIR}/host_b/sshd_config)

generate_host_config(2224 host_c ${CMAKE_CURRENT_BINARY_DIR}/host_c/sshd_config)

# generate ssh_config file
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/home/.ssh)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ssh_config.cmake ${CMAKE_CURRENT_BINARY_DIR}/home/.ssh/config)


add_custom_target(generate_test_keys ALL
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/home/.ssh/authorized_keys
    ${CMAKE_CURRENT_BINARY_DIR}/host_a/sshd_config
    ${CMAKE_CURRENT_BINARY_DIR}/host_b/sshd_config
    ${CMAKE_CURRENT_BINARY_DIR}/host_c/sshd_config
    ${CMAKE_CURRENT_BINARY_DIR}/ssh_config
    ${CMAKE_CURRENT_BINARY_DIR}/fake_passwd
)


# generate autohorized_keys file
add_custom_command(OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/home/.ssh/authorized_keys
    COMMAND cat ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_rsa.pub
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ecdsa256.pub
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ecdsa384.pub
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ecdsa521.pub
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ed25519.pub
            > ${CMAKE_CURRENT_BINARY_DIR}/home/.ssh/authorized_keys
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_rsa
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ecdsa256
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ecdsa384
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ecdsa521
            ${CMAKE_CURRENT_BINARY_DIR}/user_keys/test_ed25519
    COMMENT "Generating authorized_keys file for tests")

add_executable(lock_unlock_agent lock_unlock_agent.cpp)
target_link_libraries(lock_unlock_agent ssha)

add_library(home_replace SHARED home_replace.c)