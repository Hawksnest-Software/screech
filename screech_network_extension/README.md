# Screech Network Extension + Endpoint Security

This is a comprehensive macOS implementation that replicates the Linux eBPF network monitoring functionality using Apple's Network Extension Framework combined with Endpoint Security for process monitoring.

## Architecture

### Components

1. **Main Application** (`ScreechNetworkMonitor`)
   - Manages Endpoint Security client for process monitoring
   - Coordinates with Network Extension via XPC
   - Provides Linux eBPF-compatible logging output

2. **Network Extension** (`ScreechNetworkExtension`)
   - System Extension using NEFilterDataProvider
   - Monitors all network flows (TCP/UDP)
   - Extracts process information for each connection

3. **Shared Framework**
   - Common data structures and protocols
   - XPC communication interfaces
   - Logging utilities

### Features

- **Network Monitoring**: Real-time TCP/UDP flow detection
- **Process Monitoring**: Process exec, fork, exit events
- **File Monitoring**: File creation, write, and read events
- **Linux eBPF Compatibility**: Same log format as Linux version
- **Comprehensive Coverage**: Kernel-level network interception
- **Process Correlation**: Links network flows to specific processes
- **Greppable Output**: Structured logging for easy parsing and filtering

## Requirements

### Development
- macOS 11.0+ SDK
- Xcode with Network Extension entitlements
- Valid Apple Developer account
- Code signing certificates

### Runtime
- macOS 11.0+
- System Extension approval by user
- Full Disk Access permission
- Network Extension permission

## Building

### With osxcross (Cross-compilation)
```bash
# From the screech_network_extension directory
meson setup build-macos --cross-file ../cross-macos-arm64-minimal.txt
meson compile -C build-macos
```

### With Xcode (Native)
```bash
# Build using native Xcode toolchain
meson setup build-native
meson compile -C build-native
```

## Installation & Deployment

### 1. Code Signing (Required)
The binaries must be properly signed with valid certificates:

```bash
# Sign the main application
codesign --force --sign "Developer ID Application: Your Name" \
  --entitlements MainApp/ScreechMainApp.entitlements \
  ScreechNetworkMonitor

# Sign the system extension
codesign --force --sign "Developer ID Application: Your Name" \
  --entitlements NetworkExtension/ScreechNetworkExtension.entitlements \
  ScreechNetworkExtension
```

### 2. Notarization (For Distribution)
```bash
# Create a zip file
zip -r ScreechNetworkMonitor.zip ScreechNetworkMonitor ScreechNetworkExtension

# Submit for notarization
xcrun notarytool submit ScreechNetworkMonitor.zip \
  --apple-id your-apple-id@example.com \
  --password your-app-password \
  --team-id YOUR_TEAM_ID

# Staple the notarization
xcrun stapler staple ScreechNetworkMonitor
```

### 3. System Extension Installation
The Network Extension requires user approval:

1. Run the main application with sudo
2. macOS will prompt for System Extension approval
3. Go to System Preferences > Security & Privacy > General
4. Click "Allow" for the Screech system extension

## Usage

### Basic Usage
```bash
sudo ./ScreechNetworkMonitor
```

### Expected Output
The application will produce output similar to the Linux eBPF version:

```
[2024-01-15 10:30:45.123] NEW CONNECTION: TCP 192.168.1.100:54321 -> 142.250.191.14:443 (PID: 1234, Process: Safari)
[2024-01-15 10:30:45.124] EXEC: curl (PID: 1235)
[2024-01-15 10:30:45.125] NEW CONNECTION: TCP 192.168.1.100:54322 -> 93.184.216.34:80 (PID: 1235, Process: curl)
[2024-01-15 10:30:45.126] FILE_CREATE: TextEdit -> /Users/user/document.txt (PID: 1236, Process: TextEdit, Size: 0 bytes)
[2024-01-15 10:30:45.127] FILE_WRITE: TextEdit -> /Users/user/document.txt (PID: 1236, Process: TextEdit, Size: 1024 bytes)
[2024-01-15 10:30:45.128] FILE_READ: cat -> /Users/user/document.txt (PID: 1237, Process: cat, Size: 1024 bytes)
```

### Greppable Log Format
All events are logged in a structured, greppable format for easy parsing:

#### Network Events
```
[timestamp] CONN|protocol source:port->dest:port|PID:pid|PROC:name|UID:uid|PATH:path
```

#### Process Events
```
[timestamp] EVENT|type|PID:pid|PROC:name|UID:uid|PATH:path
```

#### File Events
```
[timestamp] FILE|operation|PID:pid|PROC:name|UID:uid|FILE:filename|SIZE:bytes|MODE:permissions|PATH:fullpath
```

### Filtering Examples
You can easily filter events using grep:

```bash
# Show only file creation events
grep "FILE|FILE_CREATE" screech_*.log

# Show all events from a specific process
grep "PROC:Safari" screech_*.log

# Show network connections to specific IP
grep "CONN.*192.168.1.1" screech_*.log

# Show file operations on documents
grep "FILE.*\.txt\|FILE.*\.doc" screech_*.log
```

### Log Files
Logs are written to per-process files:
- `screech_Safari.log`
- `screech_curl.log`
- `screech_unknown_process.log`

## Permissions

### System Preferences Configuration

1. **Full Disk Access**
   - System Preferences > Security & Privacy > Privacy > Full Disk Access
   - Add ScreechNetworkMonitor

2. **Network Extension**
   - Automatically prompted when first run
   - Can be managed in System Preferences > Network > Filter

### Required Entitlements

#### Main Application
- `com.apple.developer.endpoint-security.client`
- `com.apple.developer.networking.networkextension`
- `com.apple.developer.system-extension.install`

#### Network Extension
- `com.apple.developer.networking.networkextension`
- `com.apple.developer.system-extension.install`

## Comparison with Linux eBPF

| Feature | Linux eBPF | macOS Network Extension |
|---------|------------|------------------------|
| Network Monitoring | ✅ Kernel kprobes | ✅ NEFilterDataProvider |
| Process Monitoring | ✅ eBPF events | ✅ Endpoint Security |
| TCP/UDP Detection | ✅ Socket syscalls | ✅ Network flows |
| Process Correlation | ✅ PID extraction | ✅ Audit tokens |
| Invisible Monitoring | ✅ Kernel level | ✅ System extension |
| Root Required | ✅ Yes | ✅ Yes |
| Log Format | ✅ Compatible | ✅ Compatible |

## Troubleshooting

### Common Issues

1. **"Operation not permitted"**
   - Ensure running with sudo
   - Check Full Disk Access permissions
   - Verify code signing

2. **"System extension blocked"**
   - Go to System Preferences > Security & Privacy
   - Click "Allow" for Screech system extension
   - Reboot if necessary

3. **"Network extension not working"**
   - Check Network preferences for filter
   - Verify entitlements are correct
   - Check Console app for extension logs

### Debug Mode
Set environment variable for verbose logging:
```bash
export SCREECH_DEBUG=1
sudo ./ScreechNetworkMonitor
```

### System Logs
Check system logs for detailed information:
```bash
# View system extension logs
log show --predicate 'subsystem == "com.screech"' --last 1h

# View network extension logs
log show --predicate 'category == "networking"' --last 1h
```

## Limitations

1. **Requires valid Apple Developer account** for proper signing
2. **User approval required** for system extension installation  
3. **macOS 11.0+ only** (Network Extension requirements)
4. **Cannot be distributed via App Store** (uses system extensions)
5. **Requires notarization** for distribution outside organization

## Security Considerations

- The application requires extensive system permissions
- Network Extension runs as root with kernel access
- All network traffic is observable but not stored
- Process information is logged but arguments are sanitized
- Logs contain only metadata, not actual network content

## Development Notes

This implementation provides the most comprehensive network monitoring possible on macOS, equivalent to Linux eBPF capabilities. The Network Extension approach is the official Apple-recommended method for system-level network monitoring and provides the deepest integration with the macOS networking stack.
