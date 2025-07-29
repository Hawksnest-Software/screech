project('screech_obfuscation', 'objc',
  version : '1.0.0',
  default_options : ['warning_level=3',
                     'objc_std=c11'])

# macOS framework dependencies
foundation_dep = dependency('appleframeworks', modules : ['Foundation'])

# System libraries
thread_dep = dependency('threads')

# Source files
obfuscation_sources = [
  'ScreechObfuscation.m'
]

# Header files
obfuscation_headers = [
  'ScreechObfuscation.h'
]

# Static library target
screech_obfuscation_lib = static_library('screech_obfuscation',
  obfuscation_sources,
  dependencies : [foundation_dep, thread_dep],
  install : true,
  install_dir : get_option('libdir'),
  objc_args : [
    '-fobjc-arc',
    '-fno-objc-exceptions',
    '-Wno-unused-parameter',
    '-Wno-unused-variable',
    '-Os',  # Optimize for size
    '-ffunction-sections',
    '-fdata-sections'
  ]
)

# Install headers
install_headers(obfuscation_headers,
  subdir : 'screech_obfuscation')

# Dependency for other projects
screech_obfuscation_dep = declare_dependency(
  link_with : screech_obfuscation_lib,
  include_directories : include_directories('.'),
  dependencies : [foundation_dep, thread_dep]
)

# pkg-config file
pkg = import('pkgconfig')
pkg.generate(screech_obfuscation_lib,
  description : 'Screech Anti-Hooking and Obfuscation Library',
  name : 'screech_obfuscation',
  filebase : 'screech_obfuscation',
  version : meson.project_version(),
  url : 'https://github.com/hawksnest/screech'
)
