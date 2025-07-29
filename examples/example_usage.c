#include "cert_obfuscation.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * Example usage of the certificate obfuscation system
 * This demonstrates how to load and use the obfuscated certificate in your IDS
 */

void print_certificate_info(SecCertificateRef cert_ref) {
    if (!cert_ref) {
        printf("Certificate is NULL\n");
        return;
    }
    
    // Get certificate data for inspection (optional)
    CFDataRef cert_data = SecCertificateCopyData(cert_ref);
    if (cert_data) {
        CFIndex data_length = CFDataGetLength(cert_data);
        printf("Certificate loaded successfully: %ld bytes\n", data_length);
        CFRelease(cert_data);
    }
    
    // Get certificate summary (this might be visible to malware, use with caution)
    CFStringRef summary = SecCertificateCopySubjectSummary(cert_ref);
    if (summary) {
        char summary_str[256];
        if (CFStringGetCString(summary, summary_str, sizeof(summary_str), kCFStringEncodingUTF8)) {
            printf("Certificate Subject: %s\n", summary_str);
        }
        CFRelease(summary);
    }
}

int main(int argc, char *argv[]) {
    printf("IDS Certificate Obfuscation Demo\n");
    printf("================================\n\n");
    
    // Load the obfuscated certificate
    SecCertificateRef certificate = NULL;
    cert_obfus_error_t result = load_obfuscated_certificate(&certificate);
    
    switch (result) {
        case CERT_OBFUS_SUCCESS:
            printf("✓ Certificate loaded successfully\n");
            break;
            
        case CERT_OBFUS_ERROR_SECTION_NOT_FOUND:
            printf("✗ Error: Certificate section not found in binary\n");
            printf("  Make sure you've run the encrypt_cert.py script\n");
            return 1;
            
        case CERT_OBFUS_ERROR_DECRYPTION_FAILED:
            printf("✗ Error: Certificate decryption failed\n");
            printf("  Check encryption parameters and try again\n");
            return 1;
            
        case CERT_OBFUS_ERROR_CERT_CREATION_FAILED:
            printf("✗ Error: Failed to create certificate object\n");
            printf("  The decrypted data may not be a valid certificate\n");
            return 1;
            
        case CERT_OBFUS_ERROR_MEMORY_ALLOC_FAILED:
            printf("✗ Error: Memory allocation failed\n");
            return 1;
            
        default:
            printf("✗ Error: Unknown error occurred (%d)\n", result);
            return 1;
    }
    
    // Print certificate information
    print_certificate_info(certificate);
    
    // Optional: Verify certificate chain
    printf("\nVerifying certificate chain...\n");
    cert_obfus_error_t verify_result = verify_certificate_chain(certificate);
    
    if (verify_result == CERT_OBFUS_SUCCESS) {
        printf("✓ Certificate chain verification passed\n");
    } else {
        printf("⚠ Certificate chain verification failed (this may be expected for self-signed certs)\n");
    }
    
    // Example: Use certificate for signature verification
    printf("\nCertificate is ready for use in signature verification\n");
    printf("In a real IDS, you would:\n");
    printf("1. Use this certificate to verify signed updates\n");
    printf("2. Validate configuration file signatures\n");
    printf("3. Authenticate with remote management systems\n");
    printf("4. Sign your own detection reports\n");
    
    // Clean up
    if (certificate) {
        CFRelease(certificate);
        printf("\n✓ Certificate reference cleaned up\n");
    }
    
    printf("\nDemo completed successfully!\n");
    return 0;
}

/**
 * Alternative usage pattern for stealth operations
 */
void stealth_certificate_usage_example() {
    printf("\n--- Stealth Usage Pattern ---\n");
    
    // In a real IDS, you might want to:
    // 1. Load certificate only when needed
    // 2. Use it immediately
    // 3. Clear it from memory ASAP
    
    SecCertificateRef temp_cert = NULL;
    
    // Load certificate just before use
    if (load_obfuscated_certificate(&temp_cert) == CERT_OBFUS_SUCCESS) {
        
        // Use certificate for specific operation (signature verification, etc.)
        // ... your signature verification code here ...
        
        // Immediately release after use
        CFRelease(temp_cert);
        temp_cert = NULL;
        
        printf("Certificate used and cleared from memory\n");
    }
    
    // At this point, certificate data should be minimal in memory
    // The encrypted version remains in the Mach-O section but is much harder to detect
}
