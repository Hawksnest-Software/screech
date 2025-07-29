#ifndef CERT_OBFUSCATION_H
#define CERT_OBFUSCATION_H

#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <mach-o/getsect.h>
#include <mach-o/ldsyms.h>
#include <stdint.h>
#include <stdbool.h>

// Configuration
#define CERT_SECTION_NAME "__cert_data"
#define CERT_SEGMENT_NAME "__DATA"
#define XOR_KEY_SIZE 32
#define AES_KEY_SIZE 32

// Error codes
typedef enum {
    CERT_OBFUS_SUCCESS = 0,
    CERT_OBFUS_ERROR_SECTION_NOT_FOUND = -1,
    CERT_OBFUS_ERROR_DECRYPTION_FAILED = -2,
    CERT_OBFUS_ERROR_CERT_CREATION_FAILED = -3,
    CERT_OBFUS_ERROR_MEMORY_ALLOC_FAILED = -4
} cert_obfus_error_t;

// Encrypted certificate header
typedef struct {
    uint32_t magic;           // Magic number for validation
    uint32_t cert_size;       // Size of original certificate
    uint32_t encrypted_size;  // Size of encrypted data
    uint8_t xor_key[XOR_KEY_SIZE];  // XOR key for first layer
    uint8_t salt[16];         // Salt for key derivation
    uint8_t iv[16];           // AES IV
    // Encrypted certificate data follows
} __attribute__((packed)) cert_header_t;

// Function prototypes
cert_obfus_error_t load_obfuscated_certificate(SecCertificateRef *cert_ref);
cert_obfus_error_t verify_certificate_chain(SecCertificateRef cert_ref);
void secure_zero_memory(void *ptr, size_t size);
static cert_obfus_error_t decrypt_certificate_data(const uint8_t *encrypted_data, 
                                                  size_t encrypted_size,
                                                  const uint8_t *xor_key,
                                                  const uint8_t *salt,
                                                  const uint8_t *iv,
                                                  uint8_t **decrypted_data,
                                                  size_t *decrypted_size);

#endif // CERT_OBFUSCATION_H
