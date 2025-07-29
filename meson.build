project('screech', ['c', 'cpp', 'objc', 'objcpp'],
  version : '2.0.0',
  default_options : [
    'warning_level=3',
    'cpp_std=c++17',
    'c_std=c11',
    'optimization=2',
    'debug=false'
  ])

# macOS-specific configuration
if host_machine.system() == 'darwin'
  add_global_arguments([
    '-DTARGET_OS_MAC=1',
    '-arch', 'arm64',
    '-mmacosx-version-min=11.0'
  ], language : ['c', 'cpp', 'objc', 'objcpp'])
  
  add_global_link_arguments([
    '-arch', 'arm64',
    '-mmacosx-version-min=11.0'
  ], language : ['c', 'cpp', 'objc', 'objcpp'])
endif

# Define compiler flags for polymorphic features
compile_args = []
if get_option('enable_network_mode')
  compile_args += ['-DENABLE_NETWORK_MODE=1']
endif
if get_option('enable_obfuscation')
  compile_args += ['-DENABLE_OBFUSCATION=1']
endif
if get_option('enable_libpcap')
  compile_args += ['-DENABLE_LIBPCAP=1']
endif
if get_option('enable_vpn_mimicry')
  compile_args += ['-DENABLE_VPN_MIMICRY=1']
endif
if get_option('enable_integrity_monitoring')
  compile_args += ['-DENABLE_INTEGRITY_MONITORING=1']
endif

# macOS-only features
if host_machine.system() == 'darwin'
  if get_option('enable_dtrace_mode')
    compile_args += ['-DENABLE_DTRACE_MODE=1']
  endif
  if get_option('enable_endpoint_security')
    compile_args += ['-DENABLE_ENDPOINT_SECURITY=1']
  endif
  if get_option('enable_network_extension')
    compile_args += ['-DENABLE_NETWORK_EXTENSION=1']
  endif
endif

# Linux-only features
if host_machine.system() == 'linux'
  if get_option('enable_ebpf')
    compile_args += ['-DENABLE_EBPF=1']
  endif
endif

# Set default mode
default_mode = get_option('default_mode')
if default_mode == 'network'
  compile_args += ['-DDEFAULT_MODE_NETWORK=1']
elif default_mode == 'dtrace'
  compile_args += ['-DDEFAULT_MODE_DTRACE=1']
endif

add_global_arguments(compile_args, language : ['c', 'cpp', 'objc', 'objcpp'])

# Get compiler
cc = meson.get_compiler('c')

# Find required frameworks and dependencies
if host_machine.system() == 'darwin'
  foundation_dep = dependency('foundation', required : true)
  corefoundation_dep = dependency('corefoundation', required : true)
else
  # Dummy dependencies for non-macOS platforms
  foundation_dep = declare_dependency()
  corefoundation_dep = declare_dependency()
endif

# System frameworks for macOS
if host_machine.system() == 'darwin'
  security_framework = dependency('appleframeworks', modules : ['Security'], required : true)
  # EndpointSecurity is a library, not a framework in the SDK
  endpointsecurity_framework = cc.find_library('EndpointSecurity', required: false)
  networkextension_framework = dependency('appleframeworks', modules : ['NetworkExtension'], required : true)
  
  # System libraries
  pthread_dep = dependency('threads', required : true)
  dl_dep = meson.get_compiler('c').find_library('dl', required : true)
  proc_dep = meson.get_compiler('c').find_library('proc', required : true)
  bsm_dep = meson.get_compiler('c').find_library('bsm', required : true)
else
  # Dummy dependencies for non-macOS platforms
  security_framework = declare_dependency()
  endpointsecurity_framework = declare_dependency()
  networkextension_framework = declare_dependency()
  
  # System libraries for Linux
  pthread_dep = dependency('threads', required : true)
  dl_dep = meson.get_compiler('c').find_library('dl', required : true)
  proc_dep = declare_dependency()  # proc is macOS-specific
  bsm_dep = declare_dependency()   # bsm is macOS-specific
endif

# Include directories
inc_dirs = include_directories(
  'include',
  'include/core',
  'include/platform',
  'include/obfuscation',
  'include/network',
  'libs',
  'libs/obfuscation',
  'libs/debug_logging',
  'libs/event_logger',
  'libs/macos/process_monitor',
  'libs/macos/file_monitor',
  'libs/libpcap_monitor',
  'libs/macos/native_network_extension_monitor/include'
)

# Platform-specific obfuscation libraries
if host_machine.system() == 'darwin'
  # macOS obfuscation utilities
  string_obfuscation_macos_sources = files([
    'src/obfuscation/mac/string_obfuscation.c'
  ])

  string_obfuscation_macos_lib = static_library('string_obfuscation_macos',
    string_obfuscation_macos_sources,
    include_directories : inc_dirs,
    install : false
  )

  function_obfuscation_macos_sources = files([
    'src/obfuscation/mac/function_obfuscation.c'
  ])

  function_obfuscation_macos_lib = static_library('function_obfuscation_macos',
    function_obfuscation_macos_sources,
    include_directories : inc_dirs,
    link_with : [string_obfuscation_macos_lib],
    install : false
  )

  # macOS obfuscation engine (stealth_logging redirects to debug_logging)
  obfuscation_macos_sources = files([
    'src/obfuscation/mac/obfuscation_engine.c',
    'src/obfuscation/mac/api_misdirection.c',
    'src/obfuscation/mac/call_diversification.c',
    'src/obfuscation/mac/variant_generator.c',
    'src/obfuscation/mac/timing_obfuscation.c',
    'src/obfuscation/obfuscation_config.c'
  ])

  obfuscation_lib = static_library('obfuscation_macos_engine',
    obfuscation_macos_sources,
    include_directories : inc_dirs,
    dependencies : [pthread_dep, dl_dep],
    link_with : [string_obfuscation_macos_lib, function_obfuscation_macos_lib],
    install : false
  )

elif host_machine.system() == 'linux'
  # Linux obfuscation utilities (placeholder)
  string_obfuscation_linux_sources = files([
    'src/obfuscation/linux/string_obfuscation.c'
  ])

  string_obfuscation_linux_lib = static_library('string_obfuscation_linux',
    string_obfuscation_linux_sources,
    include_directories : inc_dirs,
    install : false
  )

  function_obfuscation_linux_sources = files([
    'src/obfuscation/linux/function_obfuscation.c'
  ])

  function_obfuscation_linux_lib = static_library('function_obfuscation_linux',
    function_obfuscation_linux_sources,
    include_directories : inc_dirs,
    link_with : [string_obfuscation_linux_lib],
    install : false
  )

  # Linux obfuscation engine (placeholder)
  obfuscation_linux_sources = files([
    'src/obfuscation/linux/obfuscation_engine.c'
  ])

  obfuscation_lib = static_library('obfuscation_linux_engine',
    obfuscation_linux_sources,
    include_directories : inc_dirs,
    dependencies : [pthread_dep, dl_dep],
    link_with : [string_obfuscation_linux_lib, function_obfuscation_linux_lib],
    install : false
  )
endif

# macOS bridge (Objective-C for stealthy operations)
if host_machine.system() == 'darwin'
  macos_bridge_sources = files([
    'src/obfuscation/mac/macos_obfuscation_bridge.m'
  ])

  macos_bridge_lib = static_library('macos_bridge',
    macos_bridge_sources,
    include_directories : inc_dirs,
    dependencies : [
      foundation_dep,
      security_framework,
      pthread_dep,
      dl_dep,
      proc_dep
    ],
    link_with : [string_obfuscation_macos_lib, function_obfuscation_macos_lib],
    install : false
  )

  # VPN Mimicry Framework - conditional compilation
  if get_option('enable_vpn_mimicry')
    vpn_mimicry_sources = files([  
      'screech_network_extension/Shared/VPNMimicryFramework.m',  
      'screech_network_extension/Shared/AntiHookingFramework.m',  
      'screech_network_extension/Shared/SystemFramework.m',  
      'screech_network_extension/MainApp/ScreechMainApp.m'  
    ])  

    vpn_mimicry_lib = static_library('vpn_mimicry',  
      vpn_mimicry_sources,  
      include_directories : [  
        inc_dirs,  
        include_directories('screech_network_extension/Shared'),  
        include_directories('screech_network_extension/MainApp')  
      ],  
      dependencies : [  
        foundation_dep,
        networkextension_framework,
        security_framework,
        endpointsecurity_framework,
        pthread_dep,
        dl_dep,
        proc_dep,
        bsm_dep  
      ],  
      install : false  
    )
  endif
endif

# macOS Process monitor library
if host_machine.system() == 'darwin'
  process_monitor_sources = files([
    'libs/macos/process_monitor/ProcessMonitor.mm'
  ])

  process_monitor_lib = static_library('process_monitor',
    process_monitor_sources,
    include_directories : inc_dirs,
    dependencies : [
      pthread_dep,
      endpointsecurity_framework,
      proc_dep,
      bsm_dep
    ],
    install : false
  )
endif

# macOS File monitor library  
if host_machine.system() == 'darwin'
  file_monitor_sources = files([
    'libs/macos/file_monitor/FileMonitor.mm'
  ])

  file_monitor_lib = static_library('file_monitor',
    file_monitor_sources,
    include_directories : inc_dirs,
    dependencies : [
      pthread_dep,
      endpointsecurity_framework,
      proc_dep,
      bsm_dep
    ],
    install : false
  )
endif

# Libpcap monitor library (cross-platform)
if get_option('enable_libpcap')
  libpcap_dep = dependency('libpcap', required: true)

  # Use different source files based on platform
  if host_machine.system() == 'darwin'
    libpcap_monitor_sources = files([
      'libs/libpcap_monitor/NetworkMonitor.mm'
    ])
  else
    libpcap_monitor_sources = files([
      'libs/libpcap_monitor/NetworkMonitor.cpp'
    ])
  endif

  libpcap_monitor_lib = static_library('libpcap_monitor',
    libpcap_monitor_sources,
    include_directories : inc_dirs,
    dependencies : [
      pthread_dep,
      libpcap_dep
    ],
    install : false
  )
endif

# macOS Network Extension library (advanced macOS-specific implementation)
if host_machine.system() == 'darwin'
  macos_network_extension_sources = files([
    'libs/macos/native_network_extension_monitor/src/screech_macos_network.mm'
  ])

  macos_network_extension_lib = static_library('macos_network_extension',
    macos_network_extension_sources,
    include_directories : [
      inc_dirs,
      include_directories('libs/macos/native_network_extension_monitor/include')
    ],
    dependencies : [
      pthread_dep,
      endpointsecurity_framework,
      networkextension_framework,
      proc_dep,
      bsm_dep
    ],
    install : false
  )
endif

# Debug Logger library (cross-platform, moved from obfuscation)
debug_logger_sources = files([
  'libs/debug_logging/debug_logging.c'
])

debug_logger_lib = static_library('debug_logger',
  debug_logger_sources,
  include_directories : inc_dirs,
  install : false
)

# Event Logger library (cross-platform)
event_logger_sources = files([
  'libs/event_logger/EventLogger.cpp'
])

event_logger_lib = static_library('event_logger',
  event_logger_sources,
  include_directories : inc_dirs,
  dependencies : [pthread_dep],
  install : false
)

# Core sources
core_sources = files([
  'src/core/unified_monitor.cpp',
  'src/core/detection_examples.cpp'
])

# Individual implementation libraries for macOS
if host_machine.system() == 'darwin'
  # Collect enabled implementation libraries
  platform_impl_libs = []
  if get_option('enable_network_mode')
    platform_impl_libs += [macos_network_extension_lib]
  endif

elif host_machine.system() == 'linux'
  # Linux eBPF implementation - add libbpf dependency
  libbpf_dep = dependency('libbpf', required: false)
  if not libbpf_dep.found()
    libbpf_dep = cc.find_library('bpf', required: false)
  endif
  
  # Find clang for BPF compilation
  clang = find_program('clang', required: false)
  
  if clang.found()
    # Compile eBPF program with clang targeting BPF
    ebpf_object = custom_target('screech_ebpf.o',
      input: 'src/platform/linux/screech_ebpf.c',
      output: 'screech_ebpf.o',
      command: [
        clang,
        '-target', 'bpf',
        '-D__TARGET_ARCH_x86',
        '-I/usr/include',
        '-I/usr/include/bpf',
        '-Wall',
        '-O2', '-g',
        '-c', '@INPUT@',
        '-o', '@OUTPUT@'
      ],
      build_by_default: true,
      install: true,
      install_dir: 'share/screech'
    )
  else
    warning('clang not found, eBPF program will not be compiled')
  endif
  
  # Linux eBPF userspace sources (only C++, not the kernel eBPF code)
  linux_ebpf_sources = files([
    'src/platform/linux/screech_linux_ebpf.cpp'
  ])
  
  linux_ebpf_lib = static_library('screech_linux_ebpf',
    linux_ebpf_sources,
    include_directories : inc_dirs,
    dependencies : [pthread_dep, libbpf_dep],
    cpp_args: ['-Wno-pedantic'],
    install : false
  )
  
  platform_impl_libs = [linux_ebpf_lib]
endif

# Main executable sources (platform-specific)
if host_machine.system() == 'darwin'
  main_sources = files([
    'src/core/unified_monitor_working_macos.mm'
  ])
else
  main_sources = files([
    'src/core/unified_monitor_working.cpp'
  ])
endif

# Build libraries to link with
link_libraries = [
  obfuscation_lib,
  debug_logger_lib,
  event_logger_lib
]

# Add libpcap monitor if enabled
if get_option('enable_libpcap')
  link_libraries += [libpcap_monitor_lib]
endif

# Add platform implementation libraries based on enabled modes
if host_machine.system() == 'darwin'
  link_libraries += [
    macos_bridge_lib,
    process_monitor_lib,
    file_monitor_lib
  ]
  
  # Add VPN mimicry library if enabled
  if get_option('enable_vpn_mimicry')
    link_libraries += [vpn_mimicry_lib]
  endif
  
  link_libraries += platform_impl_libs
elif host_machine.system() == 'linux'
  link_libraries += platform_impl_libs
endif

# Collect all dependencies
exe_deps = [
  foundation_dep,
  corefoundation_dep,
  security_framework,
  endpointsecurity_framework,
  networkextension_framework,
  pthread_dep,
  dl_dep,
  proc_dep,
  bsm_dep
]

# Add platform-specific dependencies
if host_machine.system() == 'linux'
  exe_deps += [libbpf_dep]
endif

# Add libpcap dependency if enabled
if get_option('enable_libpcap')
  exe_deps += [libpcap_dep]
endif

# Main executable
screech_exe = executable('screech',
  main_sources,
  include_directories : inc_dirs,
  link_with : link_libraries,
  dependencies : exe_deps,
  install : true,
  install_dir : 'bin'
)

# Code signing for macOS (required for Endpoint Security and VPN mimicry)
if host_machine.system() == 'darwin'
  codesign = find_program('codesign', required : false)
  if codesign.found()
    custom_target('codesign',
      input : screech_exe,
      output : 'screech_signed',
      command : [
        codesign,
        '--force',
        '--sign', '-',
        '--entitlements', meson.current_source_dir() / 'config/screech.entitlements',
        '@INPUT@'
      ],
      build_by_default : true
    )
  endif
endif
