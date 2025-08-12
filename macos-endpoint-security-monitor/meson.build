# macOS Endpoint Security Monitor
project('macos-endpoint-security-monitor', ['c', 'cpp', 'objcpp'],
    version: '1.0.0',
    default_options: [
        'cpp_std=c++17',
        'objcpp_std=c++17',
        'warning_level=3',
        'werror=false'
    ]
)

# Compiler setup
compiler = meson.get_compiler('cpp')
objcpp_compiler = meson.get_compiler('objcpp')

# Platform-specific dependencies and flags
if host_machine.system() == 'darwin'
    # macOS specific dependencies
    foundation_dep = dependency('appleframeworks', modules: ['Foundation'])
    
    # EndpointSecurity is available as a library, not a framework in this SDK
    endpoint_security_dep = declare_dependency(
        link_args: ['-lEndpointSecurity']
    )
    
    # Compile flags for macOS
    compile_flags = ['-DTARGET_OS_MAC=1']
    objcpp_compile_flags = ['-DTARGET_OS_MAC=1']
    
    # Add DEBUG flag for debug builds
    if get_option('buildtype') == 'debug'
        compile_flags += ['-DDEBUG']
        objcpp_compile_flags += ['-DDEBUG']
    endif
else
    # Not macOS - this project is macOS-only
    error('This project requires macOS')
endif

# Include directories
inc_dirs = include_directories('.')

# Debug logging library
debug_logging_sources = [
    'debug_logging.c'
]

debug_logging_lib = static_library('debug_logging',
    debug_logging_sources,
    include_directories: inc_dirs,
    c_args: compile_flags
)

# Library: EndpointSecurity Core
endpoint_security_core_sources = [
    'libs/endpoint_security_core/EndpointSecurityCore.mm'
]

endpoint_security_core_lib = static_library('endpoint_security_core',
    endpoint_security_core_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags,
    objcpp_args: objcpp_compile_flags,
    dependencies: [foundation_dep]
)

# Library: Event Logger
event_logger_sources = [
    'libs/event_logger/EventLogger.cpp'
]

event_logger_lib = static_library('event_logger',
    event_logger_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags,
    dependencies: [foundation_dep]
)

# Library: Remote Logging
remote_logging_sources = [
    'libs/remote_logging/RemoteLogger.cpp'
]

remote_logging_lib = static_library('remote_logging',
    remote_logging_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags
)

# Library: File Monitor
file_monitor_sources = [
    'libs/file_monitor/FileMonitor.mm'
]

file_monitor_lib = static_library('file_monitor',
    file_monitor_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags,
    objcpp_args: objcpp_compile_flags,
    dependencies: [foundation_dep]
)

# Library: IPC Monitor
ipc_monitor_sources = [
    'libs/ipc_monitor/IPCMonitor.mm'
]

ipc_monitor_lib = static_library('ipc_monitor',
    ipc_monitor_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags,
    objcpp_args: objcpp_compile_flags,
    dependencies: [foundation_dep]
)

# Library: Process Monitor
process_monitor_sources = [
    'libs/process_monitor/ProcessMonitor.mm'
]

process_monitor_lib = static_library('process_monitor',
    process_monitor_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags,
    objcpp_args: objcpp_compile_flags,
    dependencies: [foundation_dep]
)

# Main executable
main_sources = [
    'main.mm'
]

macos_endpoint_security_monitor = executable('macos-endpoint-security-monitor',
    main_sources,
    include_directories: inc_dirs,
    cpp_args: compile_flags,
    objcpp_args: objcpp_compile_flags,
    dependencies: [foundation_dep, endpoint_security_dep],
    link_with: [
        debug_logging_lib,
        endpoint_security_core_lib,
        event_logger_lib,
        remote_logging_lib,
        file_monitor_lib,
        ipc_monitor_lib,
        process_monitor_lib
    ],
    install: true
)
