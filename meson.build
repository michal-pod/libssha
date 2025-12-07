project('libssha', ['cpp', 'c'], default_options: ['cpp_std=c++20'], meson_version: '>=1.1')

if meson.get_compiler('cpp').get_id() == 'msvc'
  add_project_arguments('/FC', '/D_CRT_SECURE_NO_WARNINGS', language: 'cpp')
endif

conf_data = configuration_data()
botan = dependency('botan-3', required: false)

botan_sources = []
if botan.found()
    message('Botan library found, enabling Botan support')
    conf_data.set('USE_BOTAN', true)
    botan_sources = [
        'src/providers/botan/eddsa-key.cpp',
        'src/providers/botan/edcsa-key.cpp',
        'src/providers/botan/rsa-key.cpp',
        'src/providers/botan/eddsa-pub.cpp',
        'src/providers/botan/edcsa-pub.cpp',
        'src/providers/botan/rsa-pub.cpp',
        'src/providers/botan/botan-lock.cpp',
        'src/providers/botan/botan-lock-provider.cpp'
    ]    
else
    warning('Botan library not found, disabling Botan support. This will generate non functional build.')
    conf_data.set('USE_BOTAN', false)
    botan_source = []
endif

configure_file(input: 'config.h.cmake', output: 'config.h', configuration: conf_data)

if host_machine.system() == 'windows'
    extra_defines = declare_dependency(compile_args: ['/DNOMINMAX'])
else
    extra_defines = declare_dependency()    
endif

ssha_inc = include_directories(['include', '.'])
ssha_lib = static_library('ssha', 
[
    'src/messages/message.cpp',
    'src/messages/add-identity.cpp',
    'src/messages/identities-answer.cpp',
    'src/messages/lock-message.cpp',
    'src/messages/sign-request.cpp',
    'src/messages/sign-response.cpp',
    'src/messages/extension.cpp',
    'src/messages/userauth-request.cpp',
    'src/messages/remove-identity.cpp',
    'src/extensions/extension-factory.cpp',
    'src/extensions/openssh-session-bind.cpp',
    'src/extensions/openssh-restrict-destination.cpp',
    'src/key/key-factory.cpp',
    'src/key/key-manager.cpp',
    'src/key/pub-key.cpp',
    'src/key/key.cpp',
    'src/utils/logger.cpp',
    'src/utils/deserializer.cpp',
    'src/utils/serializer.cpp',
    'src/agent/session.cpp',
    'external/SHA256.cpp',
    botan_sources
],
include_directories: ssha_inc,
dependencies: [botan, extra_defines]
    )

ssha = declare_dependency(link_with: ssha_lib, include_directories: ssha_inc)
meson.override_dependency('ssha', ssha)

if host_machine.system() == 'windows'
    test_agent = executable('test-agent', 'examples/test-agent-win.cpp', dependencies: [botan, ssha], link_args: ['ws2_32.lib'])
else
    test_agent = executable('test-agent', 'examples/test-agent.cpp', dependencies: [botan, ssha])
endif

if get_option('enable_tests')
    subdir('tests/unit')
    if build_machine.kernel() == 'linux'
        subdir('tests/integration')
    endif
endif