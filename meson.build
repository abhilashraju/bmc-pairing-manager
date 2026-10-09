project(
    'bmc-pairing-manager',
    'cpp',
    meson_version: '>=1.1.1',
    default_options: ['cpp_std=c++23', 'buildtype=debugoptimized'],
)
boost_dep = dependency('boost', version: '>= 1.86', required: true)
openssl_dep = dependency('openssl', version: '>= 3.0', required: true)
sdeventplus_dep = dependency('sdeventplus')
sdbusplus_dep = dependency('sdbusplus')
dbus_interfaces_dep = dependency('phosphor-dbus-interfaces')

# ---------------------------------------------------------------------------
# sdbusplus version detection
#
# New sdbusplus (post-2024) promotes object_path and match to the top-level
# sdbusplus namespace.  Older versions keep them under sdbusplus::message and
# sdbusplus::bus::match respectively.
#
# We probe for sdbusplus::object_path (the new-API sentinel).  When found we
# define SDBUSPLUS_NEW_API so the compat shim in sdbus_calls.hpp resolves to
# the correct types automatically.
# ---------------------------------------------------------------------------
cxx = meson.get_compiler('cpp')
# Probe for sdbusplus::match at the top-level namespace.
# This type only exists in the new sdbusplus API (post-2024).
# Older releases only have sdbusplus::bus::match::match.
if cxx.has_type(
    'sdbusplus::match',
    prefix: '#include <sdbusplus/bus/match.hpp>',
    dependencies: sdbusplus_dep,
)
    add_project_arguments('-DSDBUSPLUS_NEW_API', language: 'cpp')
    message(
        'sdbusplus: new API detected (sdbusplus::match / sdbusplus::object_path)',
    )
else
    message(
        'sdbusplus: old API detected (sdbusplus::bus::match::match / sdbusplus::message::object_path)',
    )
endif

bmc_pairing_manager_dep = declare_dependency(
    dependencies: [
        sdbusplus_dep,
        sdeventplus_dep,
        openssl_dep,
        boost_dep,
        dbus_interfaces_dep,
    ],
    include_directories: ['include'],
)
bmc_pairing_manager_default_busname = 'xyz.openbmc_project.BmcPairing'
configure_file(
    input: 'service/xyz.openbmc_project.bmc-pairing-manager.service.in',
    output: 'xyz.openbmc_project.bmc-pairing-manager.service',
    configuration: {
        'SYSTEMD_TARGET': 'multi-user.target',
        'DEFAULT_BUSNAME': bmc_pairing_manager_default_busname,
    },
    install: true,
    install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
)
if get_option('use_filesystem_strategy')
    add_project_arguments('-DUSE_FILESYSTEM_STRATEGY', language: 'cpp')
    message('pic_controller: using FileSystemStrategy for persistence')
else
    message('pic_controller: using I2CStrategy for persistence')
endif

executable(
    'bmc-pairing-manager',
    ['src/bmc_pairing_manager.cpp'],
    install: true,
    include_directories: ['src'],
    cpp_args: ['-DBOOST_ASIO_DISABLE_THREADS'],
    dependencies: bmc_pairing_manager_dep,
    install_dir: '/usr/bin',
)

install_data(
    'service/xyz.openbmc_project.bmc-pairing-manager.conf',
    install_dir: '/etc/dbus-1/system.d/',
)

install_data(
    'conf/bmc-pairing-manager.conf',
    install_dir: '/var/bmc-pairing-manager/',
)


if (get_option('pingtest') == true)
    # Install network monitor script
    install_data(
        'service/simple-fix-minimal.sh',
        install_dir: '/usr/bin',
        install_mode: 'rwxr-xr-x',
    )
    # Configure and install network monitor service
    configure_file(
        input: 'service/network-monitor.service.in',
        output: 'network-monitor.service',
        configuration: {
            'SYSTEMD_TARGET': 'multi-user.target',
            'CHECK_INTERVAL': '30',
        },
        install: true,
        install_dir: dependency('systemd').get_variable('systemdsystemunitdir'),
    )
endif
subdir('subdir')

# Include tests if enabled
if get_option('tests').enabled()
    subdir('test')
endif
