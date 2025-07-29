project('expressvpn_network_monitor', 'objc',
  version : '12.5.0',
  default_options : ['warning_level=2'])

# Platform check
if host_machine.system() != 'darwin'
  error('This project requires macOS platform')
endif

# SDK configuration
sdk_path = '/home/burningserenity/osxcross/target/SDK/MacOSX15.5.sdk'

# Framework dependencies
foundation_dep = declare_dependency(
  include_directories: include_directories(sdk_path + '/System/Library/Frameworks/Foundation.framework/Headers'),
  link_args: ['-framework', 'Foundation']
)

networkextension_dep = declare_dependency(
  include_directories: include_directories(sdk_path + '/System/Library/Frameworks/NetworkExtension.framework/Headers'),
  link_args: ['-framework', 'NetworkExtension']
)

appkit_dep = declare_dependency(
  include_directories: include_directories(sdk_path + '/System/Library/Frameworks/AppKit.framework/Headers'),
  link_args: ['-framework', 'AppKit']
)

endpoint_security_dep = declare_dependency(
  include_directories: include_directories(sdk_path + '/usr/include/EndpointSecurity'),
  link_args: ['-lEndpointSecurity', '-lbsm']
)

libproc_dep = declare_dependency(
  link_args: ['-lproc']
)

commoncrypto_dep = declare_dependency(
  link_args: ['-framework', 'Security']
)

# Shared VPN framework
vpn_framework_sources = [
  'Shared/VPNMimicryFramework.m',
  'Shared/AntiHookingFramework.m'
]

vpn_framework_lib = static_library('VPNFramework',
  vpn_framework_sources,
  dependencies: [foundation_dep, appkit_dep, commoncrypto_dep],
  install: false
)

vpn_framework_dep = declare_dependency(
  link_with: vpn_framework_lib,
  include_directories: include_directories('Shared')
)

# BSM library for audit functions
bsm_dep = declare_dependency(
  link_args: ['-lbsm']
)

# ExpressVPN-like Network Extension Provider
expressvpn_provider_sources = [
  'NetworkExtension/main.m',
  'NetworkExtension/ScreechFilterDataProvider.m'
]

expressvpn_provider = executable('ExpressVPNTunnelProvider',
  expressvpn_provider_sources,
  dependencies: [
    foundation_dep,
    networkextension_dep,
    libproc_dep,
    bsm_dep,
    vpn_framework_dep
  ],
  install: true,
  install_dir: 'SystemExtensions'
)

# ExpressVPN-like Main Application
expressvpn_main_sources = [
  'MainApp/main.m',
  'MainApp/ScreechMainApp.m'
]

expressvpn_main = executable('ExpressVPN',
  expressvpn_main_sources,
  dependencies: [
    foundation_dep,
    networkextension_dep,
    endpoint_security_dep,
    appkit_dep,
    libproc_dep,
    vpn_framework_dep
  ],
  install: true
)

# Build summary
summary({
  'VPN Client': 'ExpressVPN (Network Monitor)',
  'Network Provider': 'ExpressVPNTunnelProvider',
  'Build Type': 'VPN Client with Network Monitoring',
  'Features': 'Network flow monitoring, Process correlation, Anti-hooking protection, VPN mimicry'
})
