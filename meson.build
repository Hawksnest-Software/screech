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

# Enable general obfuscation flag if any obfuscation feature is enabled
if (get_option('enable_function_pointer_obfuscation') or
    get_option('enable_anti_disassembly') or
    get_option('enable_memory_scrambling') or
    get_option('enable_syscall_randomization') or
    get_option('enable_debugger_detection') or
    get_option('enable_vm_detection') or
    get_option('enable_env_checks') or
    get_option('enable_variant_generation') or
    get_option('enable_string_obfuscation') or
    get_option('enable_timing_obfuscation') or
    get_option('enable_direct_syscalls') or
    get_option('enable_ptrace_protection') or
    get_option('enable_anti_debug_ptrace') or
    get_option('enable_window_detection') or
    get_option('enable_memory_protection') or
    get_option('enable_runtime_introspection') or
    get_option('enable_integrity_monitoring'))
  compile_args += ['-DENABLE_OBFUSCATION=1']
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

# Generate files based on enabled features (macOS only)
if host_machine.system() == 'darwin'
  # Collect enabled features for generation
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
  
  python3 = find_program('python3', required: true)
  
  # 1. Generate bundle IDs header first (needed by other components)
  bundle_ids_generator = files('scripts/generate_bundle_ids_header.py')
  
  generated_bundle_ids = custom_target('generate_bundle_ids',
    output: 'bundle_ids.h',
    command: [
      python3,
      bundle_ids_generator,
      '--output', '@OUTPUT@',
      '--verbose'
    ],
    build_by_default: true,
    install: false
  )
  
  # 2. Generate entitlements files (depends on enabled features)
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
  
  # Generate separate entitlements file for network extension when enabled
  if get_option('enable_network_extension')
    generated_extension_entitlements = custom_target('generate_extension_entitlements',
      output: 'screech_network_extension.entitlements',
      command: [
        python3,
        entitlements_generator,
        '--output', '@OUTPUT@',
        '--features'
      ] + enabled_features + ['--extension', '--verbose'],
      build_by_default: true,
      install: false
    )
  endif
  
  # Generate separate entitlements file for endpoint security extension when enabled
  if get_option('enable_endpoint_security')
    generated_endpoint_security_entitlements = custom_target('generate_endpoint_security_entitlements',
      output: 'screech_endpoint_security_extension.entitlements',
      command: [
        python3,
        entitlements_generator,
        '--output', '@OUTPUT@',
        '--features'
      ] + enabled_features + ['--endpoint-security-extension', '--verbose'],
      build_by_default: true,
      install: false
    )
  endif
  
  # 3. Generate Info.plist files (depends on bundle IDs)
  plist_generator = files('scripts/generate_plist_files.py')
  
  # Determine which plist files to generate based on enabled features
  plist_outputs = ['screech-Info.plist']
  plist_command = [
    python3,
    plist_generator,
    '--output-dir', '@OUTDIR@',
    '--main-app',
    '--verbose'
  ]
  
  # Add network extension plist only if network extension is enabled
  if get_option('enable_network_extension')
    plist_outputs += ['screech-extension-final-Info.plist']
    plist_command += ['--network-extension']
  endif
  
  # Add endpoint security extension plist only if endpoint security is enabled
  if get_option('enable_endpoint_security')
    plist_outputs += ['screech-endpoint-security-extension-Info.plist']
    plist_command += ['--endpoint-security-extension']
  endif
  
  generated_plists = custom_target('generate_plist_files',
    output: plist_outputs,
    command: plist_command,
    build_by_default: true,
    install: false
  )
  
  # Note: Main app and Endpoint Security extensions run without sandboxing
  # Network extensions remain sandboxed as they don't require ES framework access
  message('Main app runs without sandbox restrictions for full system access')
  message('Endpoint Security extension runs without sandbox (required by ES framework)')
  message('Generating files for features: ' + ' '.join(enabled_features))
  message('Generated bundle_ids.h header will be available in build directory')
  message('Generated Info.plist files will be available in build directory')
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
  systemextensions_framework = dependency('appleframeworks', modules : ['SystemExtensions'], required : true)
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
  systemextensions_framework = declare_dependency()
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
  'src/core',
  'libs',
  'libs/obfuscation',
  'libs/debug_logging',
  'libs/event_logger',
  'libs/remote_logging',
  'libs/macos/process_monitor',
  'libs/macos/file_monitor',
  'libs/macos/ipc_monitor',
  'libs/macos/endpoint_security_core',
  'libs/libpcap_monitor',
  'libs/macos/native_network_extension_monitor/include',
  'libs/macos/endpoint_security_extension_manager/include',
  'libs/macos/xpc_client/include'
)

# Note: Generated headers will be handled by adding the generated files
# directly as sources and using Meson's built-in dependency handling

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
  # Note: direct_syscalls.c is macOS-specific and should not be compiled on Linux
  # Linux would need its own implementation

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
  # macOS EndpointSecurity Core library (shared by monitors)
  endpoint_security_core_sources = files([
    'libs/macos/endpoint_security_core/EndpointSecurityCore.mm'
  ])

  endpoint_security_core_lib = static_library('endpoint_security_core',
    endpoint_security_core_sources,
    include_directories : inc_dirs,
    dependencies : [
      pthread_dep,
      endpointsecurity_framework,
      proc_dep,
      bsm_dep
    ],
    install : false
  )

  # macOS Process monitor library
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
    link_with : [endpoint_security_core_lib],
    install : false
  )

  # macOS File monitor library  
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
    link_with : [endpoint_security_core_lib],
    install : false
  )
  
  # macOS IPC monitor library
  ipc_monitor_sources = files([
    'libs/macos/ipc_monitor/IPCMonitor.mm'
  ])

  ipc_monitor_lib = static_library('ipc_monitor',
    ipc_monitor_sources,
    include_directories : inc_dirs,
    dependencies : [
      pthread_dep,
      endpointsecurity_framework,
      proc_dep,
      bsm_dep
    ],
    link_with : [endpoint_security_core_lib],
    install : false
  )
  
  # macOS Endpoint Security Extension Manager library
  endpoint_security_extension_manager_sources = files([
    'libs/macos/endpoint_security_extension_manager/src/EndpointSecurityExtensionManager.mm'
  ])

  endpoint_security_extension_manager_lib = static_library('endpoint_security_extension_manager',
    endpoint_security_extension_manager_sources + [generated_bundle_ids],
    include_directories : inc_dirs,
    dependencies : [
      foundation_dep,
      pthread_dep,
      systemextensions_framework,
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
  # Native Network Extension Monitor sources (includes the flow detection logic)
  macos_network_extension_sources = files([
    'libs/macos/native_network_extension_monitor/src/ScreechFilterDataProvider.mm',
    'libs/macos/native_network_extension_monitor/src/NetworkExtensionManager.mm',
    'libs/macos/native_network_extension_monitor/src/extension_main.m',
    'src/core/network_filter_config.c'
  ])

  macos_network_extension_lib = static_library('macos_network_extension',
    macos_network_extension_sources + [generated_bundle_ids],
    include_directories : [
      inc_dirs,
      include_directories('libs/macos/native_network_extension_monitor/include')
    ],
    dependencies : [
      foundation_dep,
      pthread_dep,
      networkextension_framework,
      systemextensions_framework,
      security_framework,
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

# Add Objective-C++ wrapper for macOS
if host_machine.system() == 'darwin'
  event_logger_sources += files([
    'libs/event_logger/EventLogger_objc.mm'
  ])
endif

event_logger_lib = static_library('event_logger',
  event_logger_sources,
  include_directories : inc_dirs,
  dependencies : [pthread_dep, foundation_dep],
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
  # Use full main app with endpoint security monitoring
  main_sources = files([
    'src/core/screech_main.mm',
    'libs/macos/xpc_client/src/ScreechXPCClient.mm'
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
  # Endpoint security monitoring moved to separate system extension
  # Main app no longer includes endpoint security libraries
  
  # Add network extension manager library if enabled (for system extension control)
  if get_option('enable_network_extension')
    link_libraries += [macos_network_extension_lib]
  endif
  
  # Add endpoint security extension manager library if enabled (for system extension control)
  if get_option('enable_endpoint_security')
    link_libraries += [endpoint_security_extension_manager_lib]
  endif
  
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
  systemextensions_framework,
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
if host_machine.system() == 'darwin'
  # Create macOS main executable  
  screech_exe = executable('screech',
    main_sources + [generated_bundle_ids],  # Add generated header as source
    include_directories : inc_dirs,
    link_with : link_libraries,
    dependencies : exe_deps,
    install : true
  )
  
  # Create network extension system extension executable if enabled
  if get_option('enable_network_extension')
    network_ext_sources = files([
      'src/system_extension/extension_main.mm',
      'libs/macos/native_network_extension_monitor/src/ScreechFilterDataProvider.mm',
      'src/core/network_filter_config.c'
    ])
    
    # Network extension libraries
    network_ext_libs = [
      debug_logger_lib,
      event_logger_lib,
      remote_logger_lib
    ]
    
    # Network extension dependencies (including NetworkExtension framework)
    network_ext_deps = [
      foundation_dep,
      networkextension_framework,
      pthread_dep,
      bsm_dep,
      proc_dep
    ]
    
    network_ext_exe = executable('screech_network_extension',
      network_ext_sources,
      include_directories : inc_dirs,
      link_with : network_ext_libs,
      dependencies : network_ext_deps,
      install : true
    )
  endif
  
  # Create endpoint security system extension executable if enabled
  if get_option('enable_endpoint_security')
    endpoint_security_ext_sources = files([
      'src/endpoint_security_extension/endpoint_security_main.mm'
    ])
    
    # Endpoint security extension libraries
    endpoint_security_ext_libs = [
      debug_logger_lib,
      event_logger_lib,
      remote_logger_lib,
      endpoint_security_core_lib,
      process_monitor_lib,
      file_monitor_lib,
      ipc_monitor_lib
    ]
    
    # Endpoint security extension dependencies 
    endpoint_security_ext_deps = [
      foundation_dep,
      pthread_dep,
      endpointsecurity_framework,
      proc_dep,
      bsm_dep
    ]
    
    endpoint_security_ext_exe = executable('screech_endpoint_security_extension',
      endpoint_security_ext_sources,
      include_directories : inc_dirs,
      link_with : endpoint_security_ext_libs,
      dependencies : endpoint_security_ext_deps,
      install : true
    )
  endif
  
  # Create app bundle automatically after building executables
  app_bundle_script = files('scripts/create_app_bundle.sh')
  
  # Determine app bundle dependencies based on enabled features
  app_bundle_inputs = [screech_exe]
  app_bundle_depends = [screech_exe, generated_plists]
  
  if get_option('enable_network_extension')
    app_bundle_inputs += [network_ext_exe]
    app_bundle_depends += [network_ext_exe]
  endif
  
  if get_option('enable_endpoint_security')
    app_bundle_inputs += [endpoint_security_ext_exe]
    app_bundle_depends += [endpoint_security_ext_exe]
  endif
  
  app_bundle_target = custom_target('create_app_bundle',
    input : app_bundle_inputs,
    output : 'screech.app',
    command : [
      app_bundle_script[0]
    ],
    depends : app_bundle_depends,
    build_by_default : true,
    build_always_stale : true
  )
else
  # Regular executable for non-macOS
  monitor_exe = executable('monitor',
    main_sources,
    include_directories : inc_dirs,
    link_with : link_libraries,
    dependencies : exe_deps,
    install : true,
    install_dir : 'bin'
  )
endif

# Code signing for macOS (required for Endpoint Security and VPN mimicry)
if host_machine.system() == 'darwin'
  codesign = find_program('codesign', required : false)
  if codesign.found()
    custom_target('codesign_main',
      input : [screech_exe, generated_entitlements],
      output : 'screech_signed',
      command : [
        codesign,
        '--force',
        '--sign', '-',
        '--identifier', 'com.hawksnestsoftware.screech',
        '--entitlements', '@INPUT1@',
        '@INPUT0@'
      ],
      build_by_default : true
    )
    
    # Use separate entitlements for system extension if Network Extension is enabled
    if get_option('enable_network_extension')
      custom_target('codesign_extension',
        input : [network_ext_exe, generated_extension_entitlements],
        output : 'screech_network_extension_signed',
        command : [
          codesign,
          '--force',
          '--sign', '-',
          '--identifier', 'com.hawksnestsoftware.screech.screech_network_extension',
          '--entitlements', '@INPUT1@',
          '@INPUT0@'
        ],
        build_by_default : true
      )
    endif
    
    # Add endpoint security extension signing if enabled
    if get_option('enable_endpoint_security')
      custom_target('codesign_endpoint_security_extension',
        input : [endpoint_security_ext_exe, generated_endpoint_security_entitlements],
        output : 'screech_endpoint_security_extension_signed',
        command : [
          codesign,
          '--force',
          '--sign', '-',
          '--identifier', 'com.hawksnestsoftware.screech.screech_endpoint_security_extension',
          '--entitlements', '@INPUT1@',
          '@INPUT0@'
        ],
        build_by_default : true
      )
    endif
  endif
endif
