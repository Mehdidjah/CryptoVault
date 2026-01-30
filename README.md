# CryptoVault

A comprehensive C++ cryptographic library providing advanced AES encryption capabilities with 10 powerful features for secure data protection, file encryption, and authenticated encryption.

## Overview

CryptoVault is a production-ready cryptographic library that implements the Advanced Encryption Standard (AES) with multiple cipher modes and advanced security features. Built from the ground up in C++11, it provides a complete toolkit for encryption, decryption, key management, and secure data storage.

## Features

### 1. PBKDF2 Key Derivation
Derive cryptographically secure keys from human-readable passwords using PBKDF2-HMAC-SHA256. Features configurable iteration counts (default: 100,000), random salt generation, and protection against brute-force attacks.

**Use Case**: Convert user passwords into encryption keys securely.

### 2. PKCS7 Padding
Industry-standard PKCS#7 padding implementation for block ciphers. Automatically adds and removes padding to make data length a multiple of block size, with automatic padding validation.

**Use Case**: Required for AES-CBC and AES-ECB modes to handle data that isn't a multiple of 16 bytes.

### 3. AES-CTR Mode
Counter mode implementation that turns AES into a stream cipher. Provides parallelizable encryption/decryption, random access to encrypted data, and no padding requirements.

**Use Case**: Stream encryption for real-time data or when padding is undesirable.

### 4. Base64 Encoding
Efficient Base64 encoding and decoding for converting binary encrypted data to text format. Includes validation and size calculation utilities.

**Use Case**: Store encrypted data in JSON/XML, transmit binary data over text protocols, or email encryption.

### 5. HMAC-SHA256
Message Authentication Code implementation using HMAC-SHA256. Provides integrity verification and authentication with constant-time comparison to prevent timing attacks.

**Use Case**: Verify data integrity and detect tampering.

### 6. Key Management
Secure key generation and management utilities. Features cryptographically secure random key generation, in-memory key storage, key derivation from passwords, hex string conversion, and secure memory wiping.

**Use Case**: Generate, store, and manage encryption keys throughout your application lifecycle.

### 7. File Encryption
Easy-to-use file encryption and decryption utilities. Supports AES-CBC with PKCS7 padding, automatic IV generation, and IV embedding options.

**Use Case**: Encrypt entire files with minimal code complexity.

### 8. Streaming Cipher
Efficiently encrypt/decrypt large files without loading entire file into memory. Processes files in configurable chunks (default: 1MB) with progress reporting callbacks.

**Use Case**: Handle large files (>100MB) efficiently without memory constraints.

### 9. Authenticated Encryption
Combine encryption with authentication for maximum security. Implements Encrypt-then-MAC approach using AES-CBC + HMAC-SHA256 with automatic key derivation.

**Use Case**: Protect against both eavesdropping and tampering attacks.

### 10. Secure Containers
Create encrypted files with metadata (like encrypted archives). Supports structured container format with metadata storage, versioning, timestamp tracking, and integrity verification.

**Use Case**: Encrypted backups with metadata, secure document storage, encrypted file archives.

## Project Structure

```
CryptoVault/
├── src/                    # Core library source files
│   ├── AES.h/cpp          # AES core implementation (ECB, CBC, CFB modes)
│   ├── AES_CTR.h/cpp      # Counter mode implementation
│   ├── AuthenticatedEncryption.h/cpp  # Encrypt-then-MAC
│   ├── Base64.h/cpp       # Base64 encoding/decoding
│   ├── FileEncryption.h/cpp  # File encryption utilities
│   ├── HMAC.h/cpp         # HMAC-SHA256 implementation
│   ├── KeyManager.h/cpp   # Key generation and management
│   ├── Padding.h/cpp      # PKCS7 padding
│   ├── PBKDF2.h/cpp       # Password-based key derivation
│   ├── SecureContainer.h/cpp  # Encrypted container format
│   └── StreamCipher.h/cpp # Streaming encryption
├── examples/               # Example code
│   └── feature_demo.cpp   # Comprehensive feature demonstration
├── tests/                 # Unit tests
├── dev/                   # Development utilities
├── speedtest/            # Performance benchmarks
├── CMakeLists.txt        # CMake build configuration
├── Makefile              # Make build configuration
└── README.md             # This file
```

## Building

### Using CMake

```bash
mkdir build
cd build
cmake ..
make
```

### Using Makefile

```bash
make build_demo    # Build feature demonstration
make demo          # Run demonstration
```

### Docker Build

```bash
docker-compose up -d
make build_demo
make demo
```

## Quick Start

### Basic Encryption

```cpp
#include "AES.h"
#include "KeyManager.h"

// Generate a key
auto key = KeyManager::generateAES256Key();

// Create AES instance
AES aes(AESKeyLength::AES_256);

// Encrypt data
std::vector<unsigned char> plaintext = {1, 2, 3, 4, 5};
std::vector<unsigned char> iv(16, 0);  // Use random IV in production!
auto ciphertext = aes.EncryptCBC(plaintext, key, iv);

// Decrypt data
auto decrypted = aes.DecryptCBC(ciphertext, key, iv);
```

### File Encryption

```cpp
#include "FileEncryption.h"
#include "KeyManager.h"

FileEncryption fileEnc(AESKeyLength::AES_256);
auto key = KeyManager::generateAES256Key();

// Encrypt file (IV is automatically generated and embedded)
auto iv = fileEnc.encryptFileWithIV("input.txt", "encrypted.bin", key);

// Decrypt file
fileEnc.decryptFileWithIV("encrypted.bin", "output.txt", key);
```

### Authenticated Encryption

```cpp
#include "AuthenticatedEncryption.h"
#include "KeyManager.h"

AuthenticatedEncryption authEnc(AESKeyLength::AES_256);
auto key = KeyManager::generateAES256Key();

// Encrypt with authentication
std::string message = "Secret data";
auto encrypted = authEnc.encrypt(message, key);

// Decrypt and verify
try {
    std::string decrypted = authEnc.decryptToString(encrypted, key);
} catch (const std::exception& e) {
    // Authentication failed - data was tampered with!
}
```

### Password-Based Key Derivation

```cpp
#include "PBKDF2.h"

PBKDF2 pbkdf2;
std::string password = "user_password";
auto salt = PBKDF2::generateSalt(16);
auto key = pbkdf2.deriveKey(password, salt, 100000, 32);
```

### Secure Containers

```cpp
#include "SecureContainer.h"
#include "KeyManager.h"

SecureContainer container;
auto key = KeyManager::generateAES256Key();

// Create container with metadata
std::map<std::string, std::string> metadata = {
    {"filename", "document.pdf"},
    {"author", "John Doe"},
    {"confidentiality", "top-secret"}
};

std::vector<unsigned char> data = {/* your data */};
auto containerData = container.createContainer(data, key, metadata);
container.saveToFile(containerData, "secure.cvault");

// Extract later
auto loaded = container.loadFromFile("secure.cvault");
std::map<std::string, std::string> extractedMeta;
auto extractedData = container.extractFromContainer(loaded, key, extractedMeta);
```

## Security Considerations

### Best Practices

1. **Key Management**
   - Never hardcode keys in your source code
   - Use PBKDF2 for password-derived keys with at least 100,000 iterations
   - Generate new keys regularly
   - Store keys securely (HSM, key vault, or secure key management system)

2. **IV/Nonce Usage**
   - Always use random IVs/nonces
   - Never reuse IV with the same key
   - Store IV with ciphertext (it's not secret)

3. **Authentication**
   - Always use authenticated encryption for production systems
   - Verify MAC before decrypting
   - Use separate keys for encryption and MAC (handled automatically by AuthenticatedEncryption)

4. **Random Number Generation**
   - Library uses `std::random_device` for randomness
   - Ensure your system has good entropy sources
   - Consider using hardware RNG for production systems

### Performance Tips

- Use `StreamCipher` for files larger than 100MB
- Adjust chunk size based on available memory
- Use `FileEncryption` for small files (< 100MB)
- Cache derived keys when possible (PBKDF2 is intentionally slow)
- Use authenticated encryption despite slight overhead - security is worth it

## Supported AES Modes

- **ECB** (Electronic Codebook) - Basic mode, not recommended for most use cases
- **CBC** (Cipher Block Chaining) - Most common mode, requires padding
- **CFB** (Cipher Feedback) - Stream cipher mode
- **CTR** (Counter) - Stream cipher mode, parallelizable, no padding needed

## Requirements

- C++11 or later
- Standard C++ library
- CMake 3.5+ (optional, for CMake builds)
- Docker (optional, for containerized builds)

## Testing

Run the comprehensive feature demonstration:

```bash
make build_demo
make demo
```

This will demonstrate all 10 features with example usage and output.

## License

This library is provided as-is for educational and commercial use.

## Contributing

Contributions welcome! Areas for improvement:
- AES-GCM native implementation
- Hardware acceleration (AES-NI)
- Additional key derivation functions
- More cipher modes
- Performance optimizations
- Additional documentation

## Version History

- **1.0.0** - Initial release with 10 core features

## Support

For issues, questions, or contributions, please refer to the project repository.
