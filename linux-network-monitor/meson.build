project('linux-ebpf-monitor', 'c',
  version : '1.0.0',
  default_options : [
    'warning_level=3',
    'c_std=c11'
  ]
)

# Import filesystem module
fs = import('fs')

# Get compiler
cc = meson.get_compiler('c')

# System dependencies
pthread_dep = dependency('threads', required : true)
dl_dep = cc.find_library('dl', required : true)

# libbpf dependency
libbpf_dep = dependency('libbpf', required: false)
if not libbpf_dep.found()
  libbpf_dep = cc.find_library('bpf', required: false)
endif

if not libbpf_dep.found()
  error('libbpf not found - required for eBPF support')
endif

# Find clang for BPF compilation
clang = find_program('clang', required: false)
if not clang.found()
  warning('clang not found - eBPF program will not be compiled')
endif

# Include directories
inc_dirs = include_directories('.')

# Create logs directory structure with process separation
log_dir_base = get_option('prefix') / 'var/log/network-monitor'

# Kernel feature detection
kernel_features = []
kernel_profile_file = get_option('kernel_profile')

# Check if we have a kernel profile file
if kernel_profile_file != ''
  profile_path = kernel_profile_file
  if not fs.is_absolute(profile_path)
    profile_path = meson.current_source_dir() / 'config' / kernel_profile_file
  endif
  
  if fs.exists(profile_path)
    message('Using kernel profile: ' + profile_path)
    # Parse the JSON profile to extract features
    profile_data = run_command('python3', '-c', 
      'import json, sys; data=json.load(open(sys.argv[1])); print("BTF:" + str(data["bpf_features"]["btf_vmlinux"]).lower() + ",CORE:" + str(data["bpf_features"]["core_support"]).lower() + ",RINGBUF:" + str(data["bpf_features"]["ringbuf_support"]).lower() + ",KPROBE:" + str(data["tracing"]["kprobes"]).lower())', 
      profile_path, check: false)
    
    if profile_data.returncode() == 0
      features = profile_data.stdout().strip().split(',')
      foreach feature : features
        parts = feature.split(':')
        feature_name = parts[0]
        feature_value = parts[1] == 'true' ? '1' : '0'
        
        if feature_name == 'BTF'
          kernel_features += ['-DHAVE_BTF_SUPPORT=' + feature_value]
        elif feature_name == 'CORE'
          kernel_features += ['-DHAVE_BPF_CORE_SUPPORT=' + feature_value]
        elif feature_name == 'RINGBUF'
          kernel_features += ['-DHAVE_RINGBUF_SUPPORT=' + feature_value]
        elif feature_name == 'KPROBE'
          kernel_features += ['-DHAVE_KPROBE_SUPPORT=' + feature_value]
        endif
      endforeach
      
      message('Kernel features from profile:')
      foreach flag : kernel_features
        message('  ' + flag)
      endforeach
    else
      error('Failed to parse kernel profile: ' + profile_path)
    endif
  else
    error('Kernel profile not found: ' + profile_path)
  endif
else
  # Fallback to local detection if no profile specified
  message('No kernel profile specified, using local detection...')
  
  # Check for BTF support
  btf_check = run_command('sh', '-c', 'test -f /sys/kernel/btf/vmlinux', check: false)
  if btf_check.returncode() == 0
    kernel_features += ['-DHAVE_BTF_SUPPORT=1']
    message('BTF support: available')
  else
    kernel_features += ['-DHAVE_BTF_SUPPORT=0']
    message('BTF support: not available')
  endif
  
  # Check for BPF CO-RE support (requires BTF + libbpf version >= 0.6)
  if btf_check.returncode() == 0 and libbpf_dep.version().version_compare('>=0.6')
    kernel_features += ['-DHAVE_BPF_CORE_SUPPORT=1']
    message('BPF CO-RE support: available')
  else
    kernel_features += ['-DHAVE_BPF_CORE_SUPPORT=0']
    message('BPF CO-RE support: not available')
  endif
  
  # Check for ring buffer support (kernel >= 5.8)
  ringbuf_check = run_command('sh', '-c', 'test -d /sys/fs/bpf && grep -q BPF_MAP_TYPE_RINGBUF /proc/kallsyms', check: false)
  if ringbuf_check.returncode() == 0
    kernel_features += ['-DHAVE_RINGBUF_SUPPORT=1']
    message('Ring buffer support: available')
  else
    kernel_features += ['-DHAVE_RINGBUF_SUPPORT=0']
    message('Ring buffer support: not available, using perf buffer fallback')
  endif
  
  # Check for kprobe support
  kprobe_check = run_command('sh', '-c', 'test -d /sys/kernel/debug/tracing/events/syscalls', check: false)
  if kprobe_check.returncode() == 0
    kernel_features += ['-DHAVE_KPROBE_SUPPORT=1']
    message('Kprobe support: available')
  else
    kernel_features += ['-DHAVE_KPROBE_SUPPORT=0']
    message('Kprobe support: not available')
  endif
endif

# eBPF program compilation
if clang.found()
  # For cross-compilation, use target architecture 
  cross_prefix = get_option('cross_prefix')
  host_arch = host_machine.cpu_family()
  
  if cross_prefix != ''
    # Cross-compiling for ARM64
    target_arch_define = '-D__TARGET_ARCH_arm64'
    cross_include_base = '/usr/' + cross_prefix + '/usr/include'
  else
    # Native compilation
    target_arch_define = '-D__TARGET_ARCH_x86' # Default
    cross_include_base = '/usr/include'
    
    if host_arch == 'aarch64'
      target_arch_define = '-D__TARGET_ARCH_arm64'
    elif host_arch == 'x86_64'
      target_arch_define = '-D__TARGET_ARCH_x86'
    endif
  endif

  ebpf_object = custom_target('screech_ebpf.o',
    input: 'screech_ebpf.c',
    output: 'screech_ebpf.o',
    command: [
      clang,
      '-target', 'bpf',
      target_arch_define,
      kernel_features,
      '-I' + cross_include_base,
      '-I' + cross_include_base + '/bpf',
      '-I' + cross_include_base + '/linux',
      '-Wall',
      '-O2', '-g',
      '-c', '@INPUT@',
      '-o', '@OUTPUT@'
    ],
    build_by_default: true,
    install: true,
    install_dir: 'share/network-monitor'
  )
endif

# Pure C implementation for ARM cross-compilation
c_sources = files([
  'screech_linux_ebpf_c.c'
])

# Compile definitions
compile_args = [
  '-DDEBUG=1'
]

# Main executable
linux_network_monitor = executable('linux-network-monitor',
  c_sources,
  include_directories : inc_dirs,
  dependencies : [
    pthread_dep, 
    libbpf_dep,
    dl_dep
  ],
  c_args: compile_args,
  install : true,
  install_dir : 'bin'
)

# Install script to create log directories
install_data('scripts/create_log_dirs.sh', install_dir : 'bin', install_mode : 'rwxr-xr-x')

# Summary
message('Configuration Summary:')
message('  Target Architecture: ' + host_arch)
message('  libbpf found: ' + libbpf_dep.found().to_string())
message('  clang found: ' + clang.found().to_string())
message('  Log directory: ' + log_dir_base)
message('  Install directory: ' + get_option('prefix'))
