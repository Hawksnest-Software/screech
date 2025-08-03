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

# Add STDOUT_DEBUG macro for debug builds
if get_option('buildtype') == 'debug'
  compile_args += ['-DSTDOUT_DEBUG=1']
endif

# Granular obfuscation compile flags
if get_option('enable_function_pointer_obfuscation')
  compile_args += ['-DENABLE_FUNCTION_POINTER_OBFUSCATION=1']
endif
if get_option('enable_anti_disassembly')
  compile_args += ['-DENABLE_ANTI_DISASSEMBLY=1']
endif
if get_option('enable_memory_scrambling')
  compile_args += ['-DENABLE_MEMORY_SCRAMBLING=1']
endif
if get_option('enable_syscall_randomization')
  compile_args += ['-DENABLE_SYSCALL_RANDOMIZATION=1']
endif
if get_option('enable_debugger_detection')
  compile_args += ['-DENABLE_DEBUGGER_DETECTION=1']
endif
if get_option('enable_vm_detection')
  compile_args += ['-DENABLE_VM_DETECTION=1']
endif
if get_option('enable_env_checks')
  compile_args += ['-DENABLE_ENV_CHECKS=1']
endif
if get_option('enable_variant_generation')
  compile_args += ['-DENABLE_VARIANT_GENERATION=1']
endif
if get_option('enable_string_obfuscation')
  compile_args += ['-DENABLE_STRING_OBFUSCATION=1']
endif
if get_option('enable_timing_obfuscation')
  compile_args += ['-DENABLE_TIMING_OBFUSCATION=1']
endif
if get_option('enable_direct_syscalls')
  compile_args += ['-DENABLE_DIRECT_SYSCALLS=1']
endif
if get_option('enable_ptrace_protection')
  compile_args += ['-DENABLE_PTRACE_PROTECTION=1']
endif
if get_option('enable_anti_debug_ptrace')
  compile_args += ['-DENABLE_ANTI_DEBUG_PTRACE=1']
endif
if get_option('enable_window_detection')
  compile_args += ['-DENABLE_WINDOW_DETECTION=1']
endif
if get_option('enable_memory_protection')
  compile_args += ['-DENABLE_MEMORY_PROTECTION=1']
endif
if get_option('enable_runtime_introspection')
  compile_args += ['-DENABLE_RUNTIME_INTROSPECTION=1']
endif

# Other feature flags
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
endif

add_global_arguments(compile_args, language : ['c', 'cpp', 'objc', 'objcpp'])

# Generate entitlements file based on enabled features (macOS only)
if host_machine.system() == 'darwin'
  # Collect enabled features for entitlements generation
  enabled_features = []
  
  # Core features that are always enabled by default
  if get_option('enable_endpoint_security')
    enabled_features += ['enable_endpoint_security']
  endif
  if get_option('enable_network_extension')
    enabled_features += ['enable_network_extension']
  endif
  if get_option('enable_libpcap')
    enabled_features += ['enable_libpcap']
  endif
  
  # Obfuscation features (only add if enabled)
  if get_option('enable_function_pointer_obfuscation')
    enabled_features += ['enable_function_pointer_obfuscation']
  endif
  if get_option('enable_anti_disassembly')
    enabled_features += ['enable_anti_disassembly']
  endif
  if get_option('enable_memory_scrambling')
    enabled_features += ['enable_memory_scrambling']
  endif
  if get_option('enable_syscall_randomization')
    enabled_features += ['enable_syscall_randomization']
  endif
  if get_option('enable_debugger_detection')
    enabled_features += ['enable_debugger_detection']
  endif
  if get_option('enable_vm_detection')
    enabled_features += ['enable_vm_detection']
  endif
  if get_option('enable_env_checks')
    enabled_features += ['enable_env_checks']
  endif
  if get_option('enable_variant_generation')
    enabled_features += ['enable_variant_generation']
  endif
  if get_option('enable_string_obfuscation')
    enabled_features += ['enable_string_obfuscation']
  endif
  if get_option('enable_timing_obfuscation')
    enabled_features += ['enable_timing_obfuscation']
  endif
  if get_option('enable_direct_syscalls')
    enabled_features += ['enable_direct_syscalls']
  endif
  if get_option('enable_ptrace_protection')
    enabled_features += ['enable_ptrace_protection']
  endif
  if get_option('enable_anti_debug_ptrace')
    enabled_features += ['enable_anti_debug_ptrace']
  endif
  if get_option('enable_window_detection')
    enabled_features += ['enable_window_detection']
  endif
  if get_option('enable_memory_protection')
    enabled_features += ['enable_memory_protection']
  endif
  if get_option('enable_runtime_introspection')
    enabled_features += ['enable_runtime_introspection']
  endif
  if get_option('enable_integrity_monitoring')
    enabled_features += ['enable_integrity_monitoring']
  endif
  if get_option('enable_vpn_mimicry')
    enabled_features += ['enable_vpn_mimicry']
  endif
  
  # Generate entitlements file
  python3 = find_program('python3', required: true)
  entitlements_generator = files('config/generate_entitlements.py')
  
  generated_entitlements = custom_target('generate_entitlements',
    output: 'screech.entitlements',
    command: [
      python3,
      entitlements_generator,
      '--output', '@OUTPUT@',
      '--features'
    ] + enabled_features + ['--verbose'],
    build_by_default: true,
    install: false
  )
  
  message('Generating entitlements for features: ' + ' '.join(enabled_features))
endif

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
  # Core Graphics and AppKit frameworks for obfuscation bridge
  coregraphics_framework = dependency('appleframeworks', modules : ['CoreGraphics'], required : true)
  appkit_framework = dependency('appleframeworks', modules : ['AppKit'], required : true)
  
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
  coregraphics_framework = declare_dependency()
  appkit_framework = declare_dependency()
  
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
  'libs/remote_logging',
  'libs/macos/process_monitor',
  'libs/macos/file_monitor',
  'libs/libpcap_monitor',
  'libs/macos/native_network_extension_monitor/include'
)

# Platform-specific obfuscation libraries
if host_machine.system() == 'darwin'
  # macOS obfuscation utilities
  string_obfuscation_macos_sources = files([
    'libs/obfuscation/mac/string_obfuscation.c'
  ])

  string_obfuscation_macos_lib = static_library('string_obfuscation_macos',
    string_obfuscation_macos_sources,
    include_directories : inc_dirs,
    install : false
  )

  function_obfuscation_macos_sources = files([
    'libs/obfuscation/mac/function_obfuscation.c'
  ])

  function_obfuscation_macos_lib = static_library('function_obfuscation_macos',
    function_obfuscation_macos_sources,
    include_directories : inc_dirs,
    link_with : [string_obfuscation_macos_lib],
    install : false
  )

  # Conditional direct syscalls library
  direct_syscalls_sources = []
  if get_option('enable_direct_syscalls')
    direct_syscalls_sources = files([
      'libs/obfuscation/mac/direct_syscalls.c'
    ])
  endif

  # Conditional variant generator (contains dangerous ptrace calls)
  variant_generator_sources = []
  if get_option('enable_variant_generation') or get_option('enable_ptrace_protection') or get_option('enable_anti_debug_ptrace')
    variant_generator_sources = files([
      'libs/obfuscation/mac/variant_generator.c'
    ])
  endif
  
  # macOS obfuscation engine (stealth_logging redirects to debug_logging)
  obfuscation_macos_sources = files([
    'libs/obfuscation/mac/api_misdirection.c',
    'libs/obfuscation/mac/call_diversification.c',
    'libs/obfuscation/mac/timing_obfuscation.c',
    'libs/obfuscation/mac/macos_obfuscation_bridge.m'
  ]) + direct_syscalls_sources + variant_generator_sources

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
    'libs/obfuscation/linux/string_obfuscation.c'
  ])

  string_obfuscation_linux_lib = static_library('string_obfuscation_linux',
    string_obfuscation_linux_sources,
    include_directories : inc_dirs,
    install : false
  )

  function_obfuscation_linux_sources = files([
    'libs/obfuscation/linux/function_obfuscation.c'
  ])

  function_obfuscation_linux_lib = static_library('function_obfuscation_linux',
    function_obfuscation_linux_sources,
    include_directories : inc_dirs,
    link_with : [string_obfuscation_linux_lib],
    install : false
  )

  # Conditional direct syscalls library for Linux
  direct_syscalls_linux_sources = []
  if get_option('enable_direct_syscalls')
    direct_syscalls_linux_sources = files([
      'libs/obfuscation/mac/direct_syscalls.c'  # Same file works for both platforms
    ])
  endif

  # Linux obfuscation engine (placeholder)
  obfuscation_linux_sources = files([
    'libs/obfuscation/linux/obfuscation_engine.c'
  ]) + direct_syscalls_linux_sources

  obfuscation_lib = static_library('obfuscation_linux_engine',
    obfuscation_linux_sources,
    include_directories : inc_dirs,
    dependencies : [pthread_dep, dl_dep],
    link_with : [string_obfuscation_linux_lib, function_obfuscation_linux_lib],
    install : false
  )
endif

# macOS VPN Mimicry Framework - conditional compilation
if host_machine.system() == 'darwin'
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

# Remote Logger library (cross-platform)
remote_logger_sources = files([
  'libs/remote_logging/RemoteLogger.cpp'
])

remote_logger_lib = static_library('remote_logger',
  remote_logger_sources,
  include_directories : inc_dirs,
  dependencies : [pthread_dep],
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
  link_with : [remote_logger_lib],
  install : false
)

# Note: Core sources are now integrated into the main executable

# Individual implementation libraries for macOS
if host_machine.system() == 'darwin'
  # Collect enabled implementation libraries
  platform_impl_libs = []
  if get_option('enable_network_extension')
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
    'src/core/screech_main.cpp'
  ])
else
  main_sources = files([
    'src/core/screech_main.cpp'
  ])
endif

# Build libraries to link with
link_libraries = [
  obfuscation_lib,
  debug_logger_lib,
  remote_logger_lib,
  event_logger_lib
]

# Add libpcap monitor if enabled
if get_option('enable_libpcap')
  link_libraries += [libpcap_monitor_lib]
endif

# Add platform implementation libraries based on enabled modes
if host_machine.system() == 'darwin'
  link_libraries += [
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
  coregraphics_framework,
  appkit_framework,
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
monitor_exe = executable('monitor',
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
      input : [monitor_exe, generated_entitlements],
      output : 'monitor_signed',
      command : [
        codesign,
        '--force',
        '--sign', '-',
        '--entitlements', '@INPUT1@',
        '@INPUT0@'
      ],
      build_by_default : true
    )
  endif
endif
