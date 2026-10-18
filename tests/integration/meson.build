ssh_keys = [
  # type, size, filename, destination_folder
  # user keys
  ['rsa', '2048', 'user_test_rsa'],
  ['ecdsa', '256', 'user_test_ecdsa256'],
  ['ecdsa', '384', 'user_test_ecdsa384'],
  ['ecdsa', '521', 'user_test_ecdsa521'],
  ['ed25519', '255', 'user_test_ed25519'],
  # host_a keys
  ['rsa', '2048', 'host_a_rsa'],
  ['ecdsa', '256', 'host_a_ecdsa256'],
  ['ecdsa', '384', 'host_a_ecdsa384'],
  ['ecdsa', '521', 'host_a_ecdsa521'],
  ['ed25519', '255', 'host_a_ed25519'],
  # host_b keys
  ['rsa', '2048', 'host_b_rsa'],
  ['ecdsa', '256', 'host_b_ecdsa256'],
  ['ecdsa', '384', 'host_b_ecdsa384'],
  ['ecdsa', '521', 'host_b_ecdsa521'],
  ['ed25519', '255', 'host_b_ed25519'],
  # host_c keys
  ['rsa', '2048', 'host_c_rsa'],
  ['ecdsa', '256', 'host_c_ecdsa256'],
  ['ecdsa', '384', 'host_c_ecdsa384'],
  ['ecdsa', '521', 'host_c_ecdsa521'],
  ['ed25519', '255', 'host_c_ed25519'],
]

# Find required programs
ssh_keygen = find_program('ssh-keygen')
sshd = find_program('sshd', dirs: ['/usr/sbin', '/usr/bin', '/sbin', '/bin'])
# Generate SSH keys

ssh_key_targets = []

foreach key_info : ssh_keys
  key_type = key_info[0]
  key_size = key_info[1]
  key_filename = key_info[2]

  key_priv_name =  key_filename
  key_pub_name = key_priv_name + '.pub'

  key_priv_path = join_paths(meson.current_build_dir(), key_priv_name)

  ssh_key_targets += custom_target('generate_' + key_filename,
    output: [key_priv_name, key_pub_name],
    command: [
      ssh_keygen,
      '-t', key_type,
      '-b', key_size,
      '-f', key_priv_path,
      '-N', '',
      '-q'
    ],
    install: false,
    build_by_default: true
  )
endforeach

# Paths for the tests, the sshd, ssh and agent configuration is written by each test
ssh = find_program('ssh')
ssh_add = find_program('ssh-add')
ssh_agent = find_program('ssh-agent')

integration_config = configuration_data()
integration_config.set_quoted('SSHD_PATH', sshd.full_path())
integration_config.set_quoted('SSH_PATH', ssh.full_path())
integration_config.set_quoted('SSH_ADD_PATH', ssh_add.full_path())
integration_config.set_quoted('SSH_AGENT_PATH', ssh_agent.full_path())
integration_config.set_quoted('SSH_KEYGEN_PATH', ssh_keygen.full_path())
integration_config.set_quoted('TEST_AGENT_PATH', test_agent.full_path())
integration_config.set_quoted('KEYS_DIR', meson.current_build_dir())
configure_file(output: 'integration-config.h', configuration: integration_config)

ssha_integration_test = executable('ssha_integration_test',
    [
        'process.cpp',
        'test-environment.cpp',
        'agent-client.cpp',
        'integration-test.cpp',
        'agent_test.cpp',
        'lock_test.cpp',
        'connect_test.cpp',
        'constraints_test.cpp',
        'interop_test.cpp',
        'transport_test.cpp'
    ],
    dependencies: [ssha, botan, dependency('gmock_main')],
    install: false
)

test('integration tests', ssha_integration_test,
     depends: [test_agent] + ssh_key_targets,
     protocol: 'gtest',
     timeout: 300)

# The same tests against OpenSSH ssh-agent, so the expectations follow the reference
# implementation rather than libssha itself
test('integration tests (OpenSSH agent)', ssha_integration_test,
     depends: ssh_key_targets,
     env: {'LIBSSHA_TEST_AGENT': 'openssh'},
     protocol: 'gtest',
     timeout: 300)
