#!/usr/bin/env python3
"""
Certificate Encryption and Embedding Tool
Encrypts a certificate file and generates data for embedding in Mach-O section
"""

import os
import sys
import struct
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.backends import default_backend
import secrets

# Configuration constants
CERT_MAGIC = 0xDEADBEEF
XOR_KEY_SIZE = 32
AES_KEY_SIZE = 32
PBKDF2_ITERATIONS = 10000
PASSWORD = b"IDS_Stealth_Key_2024"

def generate_random_bytes(size):
    """Generate cryptographically secure random bytes"""
    return secrets.token_bytes(size)

def xor_encrypt(data, key):
    """First layer: XOR encryption"""
    result = bytearray(len(data))
    for i in range(len(data)):
        result[i] = data[i] ^ key[i % len(key)]
    return bytes(result)

def aes_encrypt(data, password, salt, iv):
    """Second layer: AES encryption with PBKDF2 key derivation"""
    # Derive AES key using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
        backend=default_backend()
    )
    aes_key = kdf.derive(password)
    
    # Add PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data)
    padded_data += padder.finalize()
    
    # Encrypt with AES
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data)
    encrypted_data += encryptor.finalize()
    
    return encrypted_data

def encrypt_certificate(cert_data):
    """Encrypt certificate with layered encryption (XOR + AES)"""
    print(f"Original certificate size: {len(cert_data)} bytes")
    
    # Generate random keys and IV
    xor_key = generate_random_bytes(XOR_KEY_SIZE)
    salt = generate_random_bytes(16)
    iv = generate_random_bytes(16)
    
    print("Generated encryption parameters:")
    print(f"  XOR key: {xor_key.hex()}")
    print(f"  Salt: {salt.hex()}")
    print(f"  IV: {iv.hex()}")
    
    # Layer 1: XOR encryption
    xor_encrypted = xor_encrypt(cert_data, xor_key)
    print(f"After XOR encryption: {len(xor_encrypted)} bytes")
    
    # Layer 2: AES encryption
    aes_encrypted = aes_encrypt(xor_encrypted, PASSWORD, salt, iv)
    print(f"After AES encryption: {len(aes_encrypted)} bytes")
    
    return aes_encrypted, xor_key, salt, iv

def create_cert_header(cert_size, encrypted_size, xor_key, salt, iv):
    """Create the certificate header structure"""
    header = struct.pack('<I', CERT_MAGIC)  # magic (little-endian)
    header += struct.pack('<I', cert_size)  # original cert size
    header += struct.pack('<I', encrypted_size)  # encrypted size
    header += xor_key  # XOR key (32 bytes)
    header += salt     # salt (16 bytes)
    header += iv       # IV (16 bytes)
    
    return header

def generate_c_array(data, name):
    """Generate C array declaration for binary data"""
    hex_values = [f"0x{b:02x}" for b in data]
    
    # Format as C array with proper line breaks
    lines = []
    lines.append(f"static const uint8_t {name}[] = {{")
    
    for i in range(0, len(hex_values), 16):
        line_values = hex_values[i:i+16]
        lines.append("    " + ", ".join(line_values) + ",")
    
    lines.append("};")
    
    return "\n".join(lines)

def update_source_file(source_path, encrypted_section_data):
    """Update the C source file with encrypted certificate data"""
    print(f"Updating source file: {source_path}")
    
    with open(source_path, 'r') as f:
        content = f.read()
    
    # Find the placeholder section
    start_marker = "__attribute__((section(CERT_SEGMENT_NAME \",\" CERT_SECTION_NAME)))"
    end_marker = "};"
    
    start_idx = content.find(start_marker)
    if start_idx == -1:
        raise ValueError("Could not find certificate section in source file")
    
    # Find the opening brace after the attribute
    brace_idx = content.find("{", start_idx)
    if brace_idx == -1:
        raise ValueError("Could not find opening brace for certificate section")
    
    # Find the closing brace
    end_idx = content.find(end_marker, brace_idx)
    if end_idx == -1:
        raise ValueError("Could not find closing brace for certificate section")
    
    end_idx += len(end_marker)
    
    # Generate new section content
    hex_values = [f"0x{b:02x}" for b in encrypted_section_data]
    array_content = "{\n"
    
    for i in range(0, len(hex_values), 16):
        line_values = hex_values[i:i+16]
        array_content += "    " + ", ".join(line_values)
        if i + 16 < len(hex_values):
            array_content += ","
        array_content += "\n"
    
    array_content += "};"
    
    # Replace the section
    new_content = (content[:brace_idx] + 
                  array_content + 
                  content[end_idx:])
    
    # Write back to file
    with open(source_path, 'w') as f:
        f.write(new_content)
    
    print("Source file updated successfully")

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 encrypt_cert.py <certificate.der> <source_file.c>")
        print("Example: python3 encrypt_cert.py my_cert.der cert_obfuscation.c")
        sys.exit(1)
    
    cert_path = sys.argv[1]
    source_path = sys.argv[2]
    
    # Verify files exist
    if not os.path.exists(cert_path):
        print(f"Error: Certificate file '{cert_path}' not found")
        sys.exit(1)
    
    if not os.path.exists(source_path):
        print(f"Error: Source file '{source_path}' not found")
        sys.exit(1)
    
    print(f"Encrypting certificate: {cert_path}")
    print(f"Target source file: {source_path}")
    print()
    
    # Read certificate
    try:
        with open(cert_path, 'rb') as f:
            cert_data = f.read()
    except Exception as e:
        print(f"Error reading certificate: {e}")
        sys.exit(1)
    
    # Encrypt certificate
    try:
        encrypted_data, xor_key, salt, iv = encrypt_certificate(cert_data)
    except Exception as e:
        print(f"Error encrypting certificate: {e}")
        sys.exit(1)
    
    # Create header
    header = create_cert_header(len(cert_data), len(encrypted_data), xor_key, salt, iv)
    
    # Combine header and encrypted data
    section_data = header + encrypted_data
    
    print(f"Total section size: {len(section_data)} bytes")
    print(f"Header size: {len(header)} bytes")
    print(f"Encrypted payload size: {len(encrypted_data)} bytes")
    print()
    
    # Update source file
    try:
        update_source_file(source_path, section_data)
        print("Certificate encryption and embedding completed successfully!")
    except Exception as e:
        print(f"Error updating source file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
