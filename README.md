# Screech - Network Monitoring Tool

## Directory Structure

```
screech/
├── src/                          # Source code
│   ├── core/                     # Core functionality
│   │   ├── screech.cpp           # Main screech implementation
│   │   ├── screech_main.mm       # Main entry point (Objective-C++)
│   │   ├── unified_monitor.cpp   # Unified monitoring implementation
│   │   └── detection_examples.cpp # Detection examples
│   ├── platform/                 # Platform-specific code
│   │   ├── linux/                # Linux-specific implementations
│   │   │   ├── screech_linux_ebpf.cpp
│   │   │   └── screech_ebpf.c
│   │   └── macos/                # macOS-specific implementations
│   │       ├── screech_macos_*.cpp
│   │       └── screech_dtrace.d
│   ├── obfuscation/             # Obfuscation and stealth features
│   │   ├── api_misdirection.c
│   │   ├── call_diversification.c
│   │   ├── cert_obfuscation.c
│   │   ├── macos_obfuscation_bridge.m
│   │   ├── obfuscation_engine.c
│   │   ├── stealth_logging.c
│   │   └── variant_generator.c
│   └── network/                 # Network monitoring components
├── include/                     # Header files
│   ├── core/                    # Core headers
│   ├── platform/                # Platform-specific headers
│   ├── obfuscation/            # Obfuscation headers
│   └── network/                # Network headers
├── libs/                       # External libraries and dependencies
│   ├── file_monitor/
│   ├── network_monitor/
│   ├── obfuscation/
│   └── process_monitor/
├── scripts/                    # Build and deployment scripts
│   ├── build/                  # Build-related scripts
│   ├── deployment/             # Deployment scripts
│   │   ├── install_invisible.sh
│   │   ├── deploy_screech.sh
│   │   ├── sign_and_deploy.sh
│   │   └── install_linux_ebpf.sh
│   └── certificates/          # Certificate management
│       ├── generate_csr.sh
│       ├── encrypt_cert.py
│       └── process_apple_cert.sh
├── config/                     # Configuration files and build configs
│   ├── meson.build            # Main meson build file
│   ├── meson_*.build          # Platform-specific build configs
│   ├── cross-macos-arm64.txt  # Cross-compilation config
│   ├── meson_options.txt      # Build options
│   └── screech.entitlements   # macOS entitlements
├── docs/                      # Documentation
│   ├── advanced_evasion_strategies.md
│   ├── CERTIFICATE_GUIDE.md
│   ├── more_macos_malware_detection_considerations.md
│   ├── README_EBPF_MIGRATION.md
│   ├── README_LINUX_EBPF.md
│   ├── STEALTH_ANALYSIS.md
│   └── warp_feature_request.md
├── tests/                     # Test files
│   ├── test.c
│   └── test_macos
├── examples/                  # Usage examples
│   └── example_usage.c
├── build*/                    # Build directories (generated)
├── backup_*/                  # Backup directories
├── screech_network_extension/ # macOS Network Extension
├── screech_obfuscation_lib/  # Obfuscation library
├── subprojects/              # Meson subprojects
└── README.md                 # This file
```

## Building

The project uses Meson as the build system. Configuration files are in the `config/` directory.

## Platform Support

- **Linux**: eBPF-based monitoring (see `src/platform/linux/`)
- **macOS**: Multiple implementations including network extensions (see `src/platform/macos/`)

## Features

- Network traffic monitoring
- Process monitoring
- Advanced obfuscation techniques
- Cross-platform support
- Stealth capabilities

## Documentation

See the `docs/` directory for detailed documentation on various aspects of the project.
