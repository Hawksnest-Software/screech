# Screech eBPF Migration - Invisible Network Monitoring for macOS

This document describes the migration of screech from userspace packet capture to kernel-level monitoring that is invisible to userspace programs.

## Overview

The original screech used PcapPlusPlus for userspace packet capture, which could be detected by malware and security tools. The new version implements kernel-level monitoring using:

1. **macOS Endpoint Security Framework** - Primary method for modern macOS systems
2. **DTrace** - Fallback method for older systems or when ES is unavailable
3. **Network Extension Framework** - Additional network monitoring capabilities

## Architecture Comparison

### Original (Userspace)
```
┌─────────────────┐
│   screech.cpp   │ ← Visible to userspace programs
├─────────────────┤
│  PcapPlusPlus   │ ← Uses libpcap/WinPcap
├─────────────────┤
│   Raw Sockets   │ ← Detectable network interface
├─────────────────┤
│     Kernel      │
└─────────────────┘
```

### New (Kernel-level)
```
┌─────────────────┐
│     screech     │ ← Minimal userspace footprint
├─────────────────┤
│ Endpoint Sec.   │ ← Kernel-level event subscription
├─────────────────┤
│     Kernel      │ ← Events generated here
│  ┌───────────┐  │
│  │  Network  │  │ ← Direct kernel hooks
│  │   Stack   │  │
│  └───────────┘  │
└─────────────────┘
```

## Files Overview

### Core Implementation
- `screech_macos_kernel.cpp` - Main implementation using Endpoint Security Framework
- `screech_dtrace.d` - DTrace-based fallback implementation
- `screech.entitlements` - Required entitlements for macOS code signing

### Build System
- `meson_macos.build` - Platform-aware build configuration
- Original files backed up with timestamp

### Legacy Support
- `screech.cpp` - Original implementation (backed up)
- Still builds on Linux with PcapPlusPlus

## Key Advantages

### 1. Invisibility
- **No userspace packet capture** - Cannot be detected by process monitoring
- **No raw sockets** - No unusual network interface usage
- **Kernel-level events** - Operates below userspace detection

### 2. Enhanced Information
- **Direct process correlation** - No need for `lsof`/`ps` commands
- **Real-time monitoring** - Events captured as they happen
- **Full process context** - Path, UID, GID, command line arguments

### 3. Performance
- **Minimal overhead** - Kernel events only for relevant activities
- **No packet processing** - Only connection metadata
- **Efficient filtering** - Kernel-level event filtering

## Implementation Details

### Endpoint Security Framework

The primary implementation uses macOS Endpoint Security Framework to monitor:

```cpp
es_event_type_t events[] = {
    ES_EVENT_TYPE_NOTIFY_SOCKET,    // Socket creation
    ES_EVENT_TYPE_NOTIFY_CONNECT,   // TCP connections
    ES_EVENT_TYPE_NOTIFY_SENDTO,    // UDP communications
    ES_EVENT_TYPE_NOTIFY_BIND       // Port binding
};
```

**Key Features:**
- Direct kernel event notification
- Complete process information available
- No polling or active scanning required
- Invisible to userspace process enumeration

### DTrace Fallback

For systems without Endpoint Security access:

```d
tcp:::connect-request  // TCP connection attempts
udp:::send            // UDP packet transmission
syscall::socket:*     // Socket system calls
syscall::connect:*    // Connect system calls
```

**Advantages:**
- Available on all macOS versions
- Requires only `sudo` privileges
- Rich kernel instrumentation
- Dynamic tracing capabilities

## Building and Installation

### Requirements

#### For Endpoint Security Version:
- macOS 10.15+ (Catalina or newer)
- Xcode command line tools
- Code signing certificate (can be self-signed for development)
- System Integrity Protection (SIP) configuration may be required

#### For DTrace Version:
- macOS 10.5+ (Leopard or newer)
- Administrative privileges (`sudo`)
- DTrace enabled (default on most systems)

### Build Process

1. **Backup existing project** (already done):
   ```bash
   # Backup created automatically with timestamp
   ```

2. **Build macOS version:**
   ```bash
   cp meson_macos.build meson.build
   meson setup build_macos
   meson compile -C build_macos
   ```

3. **Sign the binary:**
   ```bash
   codesign --force --sign - --entitlements screech.entitlements build_macos/screech_macos
   ```

4. **Alternative: Use DTrace version:**
   ```bash
   chmod +x screech_dtrace.d
   sudo ./screech_dtrace.d
   ```

## Usage

### Endpoint Security Version

```bash
# Requires proper entitlements and may need SIP configuration
sudo ./screech_macos
```

**First Run Setup:**
1. Grant Full Disk Access in System Preferences → Security & Privacy
2. May require SIP configuration: `csrutil enable --without debug`
3. Allow Endpoint Security client in System Preferences

### DTrace Version

```bash
# Simple sudo access required
sudo ./screech_dtrace.d
```

## Output Format

Both versions maintain the same output format for compatibility:

```
[2024-01-20 15:30:45.123] NEW CONNECTION: TCP 192.168.1.100:51234 -> 93.184.216.34:443 (PID: 1234, Process: curl)
```

**Log Files:**
- `screech_<process_name>.log` - Per-process connection logs
- Same greppable format as original

## Security Considerations

### Endpoint Security
- Requires special entitlements and code signing
- May trigger macOS security prompts
- Operates at kernel privilege level
- Monitored by macOS security systems

### DTrace
- Requires administrative privileges
- Kernel-level instrumentation visibility
- May be logged by system auditing
- Less privileged than Endpoint Security

### Detection Resistance

**What's Invisible:**
- No network interface in promiscuous mode
- No raw socket creation
- No userspace packet processing
- No external command execution (`lsof`, `ps`)

**Potential Detection Points:**
- Endpoint Security client registration (logged by macOS)
- DTrace script execution (visible in process list)
- Code signing and entitlements (system logs)
- Kernel event subscription (requires kernel-level detection)

## Migration Benefits

1. **Stealth Operation** - Invisible to standard userspace detection
2. **Better Performance** - No packet processing overhead  
3. **Richer Data** - Direct access to process information
4. **Platform Native** - Uses macOS-specific optimized APIs
5. **Future Proof** - Modern macOS security frameworks

## Troubleshooting

### Endpoint Security Issues
```bash
# Check entitlements
codesign -d --entitlements - screech_macos

# Verify code signing
codesign -v screech_macos

# Check system logs
log show --predicate 'subsystem == "com.apple.endpointsecurity"'
```

### DTrace Issues
```bash
# Check DTrace availability
sudo dtrace -n 'BEGIN { exit(0); }'

# Verify privileges
sudo dtrace -l | grep tcp:::connect-request
```

## Future Enhancements

1. **Network Extension Integration** - Additional network layer monitoring
2. **System Extension** - Persistent kernel-level monitoring
3. **Machine Learning** - Behavioral analysis of network patterns
4. **Encrypted Communications** - TLS/SSL connection analysis

## Compatibility

- **macOS 10.15+** - Full Endpoint Security support
- **macOS 10.5+** - DTrace fallback support  
- **Linux** - Original PcapPlusPlus version still available
- **Cross-platform** - Build system detects platform automatically

This migration transforms screech from a detectable userspace tool into an invisible kernel-level monitoring system, significantly enhancing its stealth capabilities for security research and malware analysis.
