# Apple Developer Certificate Guide

This guide walks you through obtaining a legitimate Apple Developer certificate for your IDS and integrating it with the obfuscation system.

## Prerequisites

- Apple ID
- $99/year for Apple Developer Program
- OpenSSL installed
- Python 3 with cryptography library

## Step 1: Generate Certificate Signing Request (CSR)

First, customize and run the CSR generation script:

```bash
# Edit the script to include your information
nano generate_csr.sh

# Update these fields:
# - COUNTRY (e.g., "US", "CA", "GB")
# - STATE (your state/province)
# - CITY (your city)
# - ORG (your organization name)
# - EMAIL (your contact email)
# - COMMON_NAME (your name or organization)

# Run the script
./generate_csr.sh
```

This creates:
- `hawksnest_developer.key` - Your private key (keep secure!)
- `hawksnest_developer.csr` - Certificate signing request

## Step 2: Join Apple Developer Program

1. **Visit**: https://developer.apple.com/programs/
2. **Sign in** with your Apple ID
3. **Choose enrollment type**:
   - **Individual**: $99/year, fastest approval
   - **Organization**: $99/year, requires legal verification (takes longer)
4. **Complete payment and verification**
5. **Wait for approval** (usually 24-48 hours)

## Step 3: Request Certificate from Apple

1. **Login to Apple Developer Portal**: https://developer.apple.com/account/
2. **Navigate to**: Certificates, Identifiers & Profiles
3. **Click**: Certificates → "+" (Add new certificate)
4. **Select certificate type**:
   - **macOS Development** (for development/testing)
   - **Developer ID Application** (for distribution outside App Store)
   - **Mac App Distribution** (for App Store distribution)

### For IDS (Recommended): Developer ID Application Certificate

1. **Select**: "Developer ID Application"
2. **Upload**: Your `hawksnest_developer.csr` file
3. **Download**: The issued certificate (usually `.cer` format)

## Step 4: Process the Certificate

Use the processing script to convert the certificate to the correct format:

```bash
# For .cer file from Apple
./process_apple_cert.sh downloaded_certificate.cer hawksnest_developer.key

# For .p12 file (if you exported from Keychain Access)
./process_apple_cert.sh certificate.p12
```

This creates:
- `hawksnest_developer.der` - Certificate in DER format (for obfuscation)
- `hawksnest_developer_final.key` - Your private key

## Step 5: Integrate with Obfuscation System

Encrypt and embed the certificate:

```bash
# Install Python dependencies if needed
pip3 install cryptography

# Encrypt the certificate and embed in source code
python3 encrypt_cert.py hawksnest_developer.der cert_obfuscation.c
```

## Step 6: Build and Test

Compile your IDS with the obfuscated certificate:

```bash
# Example compilation (adjust for your build system)
clang -framework Security -framework CoreFoundation \
      cert_obfuscation.c example_usage.c -o ids_test

# Test the certificate loading
./ids_test
```

## Certificate Types Explained

### Developer ID Application Certificate
- **Best for IDS**: Signs applications for distribution outside App Store
- **Gatekeeper approved**: Users won't see scary warnings
- **Valid for**: 5 years
- **Renewable**: Yes

### macOS Development Certificate
- **For testing only**: Not suitable for production IDS
- **Limited scope**: Only works on registered development machines
- **Valid for**: 1 year

### Mac App Distribution Certificate  
- **App Store only**: Only for Mac App Store distribution
- **Not suitable**: For standalone IDS deployment

## Security Best Practices

### Private Key Security
```bash
# Set restrictive permissions
chmod 600 hawksnest_developer.key
chmod 600 hawksnest_developer_final.key

# Store in secure location
mkdir -p ~/.ssl/private
mv hawksnest_developer_final.key ~/.ssl/private/
chmod 700 ~/.ssl/private
```

### Certificate Storage
- **Original certificate**: Keep secure backup
- **DER format**: Used for obfuscation system
- **Never commit**: Private keys to version control

## Troubleshooting

### CSR Generation Issues
```bash
# If OpenSSL is missing
# macOS: brew install openssl
# Linux: apt-get install openssl

# Verify CSR
openssl req -text -noout -verify -in hawksnest_developer.csr
```

### Certificate Issues
```bash
# Verify certificate
openssl x509 -in hawksnest_developer.der -inform DER -text -noout

# Check certificate chain
# (Important: Apple certificates should chain to Apple roots)
```

### Obfuscation Issues
```bash
# Verify Python dependencies
python3 -c "import cryptography; print('OK')"

# Check certificate file size
ls -la hawksnest_developer.der

# Verify encryption worked
hexdump -C cert_obfuscation.c | grep -A5 -B5 "DEADBEEF"
```

## Alternative: Self-Signed Certificate (Development Only)

For development/testing, you can create a self-signed certificate:

```bash
# Generate self-signed certificate (NOT for production)
openssl req -x509 -newkey rsa:2048 -keyout selfsigned.key -out selfsigned.crt \
    -days 365 -nodes -subj "/CN=HawksNest IDS Dev"

# Convert to DER
openssl x509 -in selfsigned.crt -outform DER -out selfsigned.der

# Use with obfuscation system
python3 encrypt_cert.py selfsigned.der cert_obfuscation.c
```

**Warning**: Self-signed certificates will trigger Gatekeeper warnings and are not suitable for production IDS deployment.

## Next Steps

1. **Test thoroughly**: Verify certificate loading and validation
2. **Integrate with IDS**: Use the obfuscated certificate in your detection system
3. **Plan for renewal**: Apple certificates expire (typically 5 years for Developer ID)
4. **Monitor certificate status**: Apple can revoke certificates if misused

## Support

- **Apple Developer Support**: https://developer.apple.com/support/
- **Certificate Documentation**: https://developer.apple.com/support/certificates/
- **Gatekeeper Info**: https://support.apple.com/en-us/HT202491

Remember: This certificate should only be used for legitimate IDS purposes. Misuse can result in certificate revocation and removal from the Apple Developer Program.
