#include "cert_obfuscation.h"
#include <CommonCrypto/CommonCrypto.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

// Magic number for certificate header validation
#define CERT_MAGIC 0xDEADBEEF

// Placeholder for encrypted certificate data - this will be replaced by build script
__attribute__((section(CERT_SEGMENT_NAME "," CERT_SECTION_NAME)))
static const uint8_t encrypted_cert_section[] = {
    // This section will be populated by the build script
    // For now, contains placeholder data
    0x00, 0x00, 0x00, 0x00  // Will be replaced with actual encrypted certificate
};

/**
 * Securely zero memory to prevent certificate data from lingering
 */
void secure_zero_memory(void *ptr, size_t size) {
    if (ptr == NULL || size == 0) return;
    
    volatile uint8_t *volatile_ptr = (volatile uint8_t *)ptr;
    for (size_t i = 0; i < size; i++) {
        volatile_ptr[i] = 0;
    }
    
    // Additional security: use mlock/munlock if possible
    munlock(ptr, size);
}

/**
 * Derive AES key from password and salt using PBKDF2
 */
static int derive_aes_key(const uint8_t *password, size_t password_len,
                         const uint8_t *salt, size_t salt_len,
                         uint8_t *key, size_t key_len) {
    return CCKeyDerivationPBKDF(kCCPBKDF2, 
                               (const char *)password, password_len,
                               salt, salt_len,
                               kCCPRFHmacAlgSHA256,
                               10000,  // iterations
                               key, key_len);
}

/**
 * Decrypt certificate data using layered encryption (XOR + AES)
 */
static cert_obfus_error_t decrypt_certificate_data(const uint8_t *encrypted_data, 
                                                  size_t encrypted_size,
                                                  const uint8_t *xor_key,
                                                  const uint8_t *salt,
                                                  const uint8_t *iv,
                                                  uint8_t **decrypted_data,
                                                  size_t *decrypted_size) {
    if (!encrypted_data || !xor_key || !salt || !iv || !decrypted_data || !decrypted_size) {
        return CERT_OBFUS_ERROR_DECRYPTION_FAILED;
    }
    
    // Step 1: XOR decryption (first layer)
    uint8_t *xor_decrypted = malloc(encrypted_size);
    if (!xor_decrypted) {
        return CERT_OBFUS_ERROR_MEMORY_ALLOC_FAILED;
    }
    
    for (size_t i = 0; i < encrypted_size; i++) {
        xor_decrypted[i] = encrypted_data[i] ^ xor_key[i % XOR_KEY_SIZE];
    }
    
    // Step 2: Derive AES key from hardcoded password + salt
    uint8_t aes_key[AES_KEY_SIZE];
    const char *password = "IDS_Stealth_Key_2024";  // This could be further obfuscated
    
    if (derive_aes_key((const uint8_t *)password, strlen(password),
                      salt, 16, aes_key, AES_KEY_SIZE) != kCCSuccess) {
        secure_zero_memory(xor_decrypted, encrypted_size);
        free(xor_decrypted);
        return CERT_OBFUS_ERROR_DECRYPTION_FAILED;
    }
    
    // Step 3: AES decryption (second layer)
    size_t aes_decrypted_size = encrypted_size;
    uint8_t *aes_decrypted = malloc(aes_decrypted_size);
    if (!aes_decrypted) {
        secure_zero_memory(xor_decrypted, encrypted_size);
        secure_zero_memory(aes_key, AES_KEY_SIZE);
        free(xor_decrypted);
        return CERT_OBFUS_ERROR_MEMORY_ALLOC_FAILED;
    }
    
    size_t bytes_decrypted = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt,
                                    kCCAlgorithmAES,
                                    kCCOptionPKCS7Padding,
                                    aes_key, AES_KEY_SIZE,
                                    iv,
                                    xor_decrypted, encrypted_size,
                                    aes_decrypted, aes_decrypted_size,
                                    &bytes_decrypted);
    
    // Clean up intermediate data
    secure_zero_memory(xor_decrypted, encrypted_size);
    secure_zero_memory(aes_key, AES_KEY_SIZE);
    free(xor_decrypted);
    
    if (status != kCCSuccess) {
        secure_zero_memory(aes_decrypted, aes_decrypted_size);
        free(aes_decrypted);
        return CERT_OBFUS_ERROR_DECRYPTION_FAILED;
    }
    
    *decrypted_data = aes_decrypted;
    *decrypted_size = bytes_decrypted;
    
    return CERT_OBFUS_SUCCESS;
}

/**
 * Load and decrypt the obfuscated certificate from the Mach-O section
 */
cert_obfus_error_t load_obfuscated_certificate(SecCertificateRef *cert_ref) {
    if (!cert_ref) {
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    *cert_ref = NULL;
    
    // Get the certificate section from the Mach-O binary
    unsigned long section_size = 0;
    const uint8_t *section_data = getsectiondata(&_mh_execute_header,
                                                CERT_SEGMENT_NAME,
                                                CERT_SECTION_NAME,
                                                &section_size);
    
    if (!section_data || section_size < sizeof(cert_header_t)) {
        return CERT_OBFUS_ERROR_SECTION_NOT_FOUND;
    }
    
    // Parse the certificate header
    const cert_header_t *header = (const cert_header_t *)section_data;
    
    // Validate magic number
    if (header->magic != CERT_MAGIC) {
        return CERT_OBFUS_ERROR_SECTION_NOT_FOUND;
    }
    
    // Verify section size
    if (section_size < sizeof(cert_header_t) + header->encrypted_size) {
        return CERT_OBFUS_ERROR_SECTION_NOT_FOUND;
    }
    
    // Get encrypted certificate data
    const uint8_t *encrypted_cert = section_data + sizeof(cert_header_t);
    
    // Decrypt the certificate
    uint8_t *decrypted_cert = NULL;
    size_t decrypted_size = 0;
    
    cert_obfus_error_t decrypt_result = decrypt_certificate_data(
        encrypted_cert, header->encrypted_size,
        header->xor_key, header->salt, header->iv,
        &decrypted_cert, &decrypted_size);
    
    if (decrypt_result != CERT_OBFUS_SUCCESS) {
        return decrypt_result;
    }
    
    // Verify decrypted size matches expected
    if (decrypted_size != header->cert_size) {
        secure_zero_memory(decrypted_cert, decrypted_size);
        free(decrypted_cert);
        return CERT_OBFUS_ERROR_DECRYPTION_FAILED;
    }
    
    // Create SecCertificateRef from decrypted DER data
    CFDataRef cert_data = CFDataCreate(kCFAllocatorDefault, decrypted_cert, decrypted_size);
    if (!cert_data) {
        secure_zero_memory(decrypted_cert, decrypted_size);
        free(decrypted_cert);
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, cert_data);
    
    // Clean up immediately
    secure_zero_memory(decrypted_cert, decrypted_size);
    free(decrypted_cert);
    CFRelease(cert_data);
    
    if (!certificate) {
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    *cert_ref = certificate;
    return CERT_OBFUS_SUCCESS;
}

/**
 * Verify the certificate chain (optional validation)
 */
cert_obfus_error_t verify_certificate_chain(SecCertificateRef cert_ref) {
    if (!cert_ref) {
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    // Create a certificate array
    CFArrayRef cert_array = CFArrayCreate(kCFAllocatorDefault, 
                                         (const void **)&cert_ref, 1,
                                         &kCFTypeArrayCallBacks);
    if (!cert_array) {
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    // Create trust object
    SecTrustRef trust = NULL;
    SecPolicyRef policy = SecPolicyCreateBasicX509();
    
    OSStatus status = SecTrustCreateWithCertificates(cert_array, policy, &trust);
    
    CFRelease(cert_array);
    CFRelease(policy);
    
    if (status != errSecSuccess || !trust) {
        if (trust) CFRelease(trust);
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    // Evaluate trust (this is optional - you might want to skip for stealth)
    SecTrustResultType trust_result;
    status = SecTrustEvaluate(trust, &trust_result);
    
    CFRelease(trust);
    
    if (status != errSecSuccess) {
        return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
    }
    
    // For an IDS, you might want to accept self-signed certificates
    if (trust_result == kSecTrustResultUnspecified ||
        trust_result == kSecTrustResultProceed ||
        trust_result == kSecTrustResultRecoverableTrustFailure) {
        return CERT_OBFUS_SUCCESS;
    }
    
    return CERT_OBFUS_ERROR_CERT_CREATION_FAILED;
}
