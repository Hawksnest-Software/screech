#!/bin/bash

# Process Apple Developer Certificate for use with obfuscation system
# Converts certificate from various formats to DER format

set -e

if [ $# -lt 1 ]; then
    echo "Usage: $0 <certificate_file> [private_key_file]"
    echo ""
    echo "Examples:"
    echo "  $0 hawksnest_developer.cer"
    echo "  $0 hawksnest_developer.p12 hawksnest_developer.key"
    echo "  $0 hawksnest_developer.pem"
    echo ""
    echo "Supported input formats:"
    echo "  - .cer (DER or PEM)"
    echo "  - .crt (DER or PEM)" 
    echo "  - .pem (PEM)"
    echo "  - .p12/.pfx (PKCS#12)"
    echo ""
    exit 1
fi

CERT_FILE="$1"
PRIVATE_KEY="$2"
OUTPUT_DER="hawksnest_developer.der"
OUTPUT_KEY="hawksnest_developer_final.key"

echo "Processing Apple Developer Certificate"
echo "====================================="
echo ""

if [ ! -f "$CERT_FILE" ]; then
    echo "Error: Certificate file '$CERT_FILE' not found"
    exit 1
fi

# Detect file type and convert accordingly
EXTENSION="${CERT_FILE##*.}"
EXTENSION=$(echo "$EXTENSION" | tr '[:upper:]' '[:lower:]')

case "$EXTENSION" in
    "p12"|"pfx")
        echo "Processing PKCS#12 file..."
        if [ -z "$PRIVATE_KEY" ]; then
            echo "Warning: No private key file specified for PKCS#12"
            echo "The private key will be extracted from the PKCS#12 file"
        fi
        
        # Extract certificate from PKCS#12
        echo "Enter the PKCS#12 password when prompted:"
        openssl pkcs12 -in "$CERT_FILE" -clcerts -nokeys -out temp_cert.pem
        
        # Extract private key from PKCS#12 (optional)
        echo "Extracting private key (enter password again):"
        openssl pkcs12 -in "$CERT_FILE" -nocerts -out temp_key.pem
        
        # Remove passphrase from private key
        echo "Removing passphrase from private key:"
        openssl rsa -in temp_key.pem -out "$OUTPUT_KEY"
        
        # Convert certificate to DER
        openssl x509 -in temp_cert.pem -outform DER -out "$OUTPUT_DER"
        
        # Clean up temporary files
        rm -f temp_cert.pem temp_key.pem
        
        echo "Extracted certificate: $OUTPUT_DER"
        echo "Extracted private key: $OUTPUT_KEY"
        ;;
        
    "cer"|"crt")
        echo "Processing certificate file..."
        
        # Try to determine if it's DER or PEM
        if openssl x509 -in "$CERT_FILE" -inform DER -noout 2>/dev/null; then
            echo "Certificate is already in DER format"
            cp "$CERT_FILE" "$OUTPUT_DER"
        elif openssl x509 -in "$CERT_FILE" -inform PEM -noout 2>/dev/null; then
            echo "Converting PEM certificate to DER..."
            openssl x509 -in "$CERT_FILE" -inform PEM -outform DER -out "$OUTPUT_DER"
        else
            echo "Error: Unable to parse certificate file"
            exit 1
        fi
        
        if [ -n "$PRIVATE_KEY" ] && [ -f "$PRIVATE_KEY" ]; then
            echo "Copying private key..."
            cp "$PRIVATE_KEY" "$OUTPUT_KEY"
        fi
        ;;
        
    "pem")
        echo "Converting PEM certificate to DER..."
        openssl x509 -in "$CERT_FILE" -inform PEM -outform DER -out "$OUTPUT_DER"
        
        if [ -n "$PRIVATE_KEY" ] && [ -f "$PRIVATE_KEY" ]; then
            echo "Copying private key..."
            cp "$PRIVATE_KEY" "$OUTPUT_KEY"
        fi
        ;;
        
    *)
        echo "Error: Unsupported file extension '$EXTENSION'"
        echo "Supported: .cer, .crt, .pem, .p12, .pfx"
        exit 1
        ;;
esac

# Verify the DER certificate
echo ""
echo "Verifying certificate..."
if openssl x509 -in "$OUTPUT_DER" -inform DER -noout -text > /dev/null 2>&1; then
    echo "✓ Certificate verification successful"
    
    # Display certificate info
    echo ""
    echo "Certificate Information:"
    echo "======================="
    openssl x509 -in "$OUTPUT_DER" -inform DER -noout -subject -issuer -dates
    
    # Check if it's a valid code signing certificate
    echo ""
    echo "Certificate Extensions:"
    openssl x509 -in "$OUTPUT_DER" -inform DER -noout -text | grep -A 10 "X509v3 Extended Key Usage" || echo "No Extended Key Usage found"
    
else
    echo "✗ Certificate verification failed"
    exit 1
fi

# Set secure permissions
chmod 600 "$OUTPUT_DER"
if [ -f "$OUTPUT_KEY" ]; then
    chmod 600 "$OUTPUT_KEY"
fi

echo ""
echo "Certificate processing completed!"
echo "==============================="
echo ""
echo "Output files:"
echo "  Certificate (DER): $OUTPUT_DER"
if [ -f "$OUTPUT_KEY" ]; then
    echo "  Private Key:       $OUTPUT_KEY"
fi
echo ""
echo "Next step: Use the certificate with the obfuscation system:"
echo "  python3 encrypt_cert.py $OUTPUT_DER cert_obfuscation.c"
echo ""
echo "Security reminder:"
echo "- Keep your private key secure and never share it"
echo "- The DER certificate file can be used for obfuscation"
echo "- Delete any temporary files containing sensitive data"
