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
cat = find_program('cat')
# Generate SSH keys

user_pub_key_names = []

foreach key_info : ssh_keys
  key_type = key_info[0]
  key_size = key_info[1]
  key_filename = key_info[2]

  key_priv_name =  key_filename
  key_pub_name = key_priv_name + '.pub'

  if key_filename.startswith('user_')
    user_pub_key_names += meson.current_build_dir() / key_pub_name
  endif

  key_priv_path = join_paths(meson.current_build_dir(), key_priv_name)

  custom_target('generate_' + key_filename,
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

# Configure sshd instances
sshd_instances = [
  ['host_a', 2222],
  ['host_b', 2223],
  ['host_c', 2224],
]

foreach instance : sshd_instances
  host_name = instance[0]
  port_port = instance[1]
  host_conf = configuration_data()
  host_conf.set('SSHD_PORT', port_port)
  host_conf.set('SSHD_INSTANCE_NAME', host_name)
  host_conf.set('DATA_DIR', meson.current_build_dir().replace('\\', '/'))

  configure_file(input: 'sshd_config.cmake',
                 output: host_name + '_sshd_config',
                 configuration: host_conf,
                 install: false)
endforeach


# Aggregate authorized_keys file

custom_target('aggregate_user_pub_keys',
  output: 'authorized_keys',
  command: [cat] + user_pub_key_names,
  capture: true,
  install: false,
  build_by_default: true
)

# Meson can't create target in subdirectory directly, so we create home/.ssh in a separate subdir build file
subdir('home/.ssh')

lock_unlock_agent= executable('lock_unlock_agent', 'lock_unlock_agent.cpp',
    dependencies: [ssha, botan],
    install: false
)

home_replace_lib = shared_library('home_replace', 'home_replace.c',    
    install: false
)

test_count = run_command(meson.current_source_dir() / 'tests.sh', 'count', check: true).stdout().strip().to_int()
message('Number of integration tests: ' + test_count.to_string())
integration_tests_config = configuration_data()
integration_tests_config.set('SSHD_PATH', sshd.full_path())
integration_tests_config.set('SOURCE_DIR', meson.current_source_dir())
integration_tests_config.set('TEST_AGENT_PATH', test_agent.full_path())
integration_tests_config.set('TESTS_DIRECTORY', meson.current_build_dir())
integration_tests_config.set('HOME_REPLACE_LIB', home_replace_lib.full_path())
integration_tests_config.set('LOCK_UNLOCK_AGENT_PATH', lock_unlock_agent.full_path())
integration_tests_config.set('TESTS_COUNT', test_count)

integration_tests = configure_file(input: 'integration_tests.sh.in',
                                   output: 'integration_tests.sh',
                                   configuration: integration_tests_config,
                                   install: false)
test('integration tests', integration_tests, protocol: 'tap')