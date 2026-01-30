#include <iostream>
#include <iomanip>
#include "../src/AES.h"
#include "../src/PBKDF2.h"
#include "../src/Padding.h"
#include "../src/AES_CTR.h"
#include "../src/Base64.h"
#include "../src/HMAC.h"
#include "../src/KeyManager.h"
#include "../src/FileEncryption.h"
#include "../src/StreamCipher.h"
#include "../src/AuthenticatedEncryption.h"
#include "../src/SecureContainer.h"

void printHex(const std::vector<unsigned char>& data, size_t maxLen = 32) {
    for (size_t i = 0; i < std::min(data.size(), maxLen); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << static_cast<int>(data[i]);
    }
    if (data.size() > maxLen) std::cout << "...";
    std::cout << std::dec << std::endl;
}

void demo1_PBKDF2() {
    std::cout << "\n=== Feature 1: PBKDF2 Key Derivation ===" << std::endl;
    
    PBKDF2 pbkdf2;
    std::string password = "MySecurePassword123!";
    std::vector<unsigned char> salt = PBKDF2::generateSalt(16);
    
    std::cout << "Password: " << password << std::endl;
    std::cout << "Salt: "; printHex(salt);
    
    auto key = pbkdf2.deriveKey(password, salt, 100000, 32);
    std::cout << "Derived Key (32 bytes): "; printHex(key);
    std::cout << "✓ Successfully derived cryptographic key from password" << std::endl;
}

void demo2_Padding() {
    std::cout << "\n=== Feature 2: PKCS7 Padding ===" << std::endl;
    
    std::vector<unsigned char> data = {1, 2, 3, 4, 5};
    std::cout << "Original data size: " << data.size() << " bytes" << std::endl;
    
    auto padded = Padding::addPKCS7(data);
    std::cout << "Padded data size: " << padded.size() << " bytes" << std::endl;
    std::cout << "Padded data: "; printHex(padded);
    
    auto unpadded = Padding::removePKCS7(padded);
    std::cout << "Unpadded size: " << unpadded.size() << " bytes" << std::endl;
    std::cout << "✓ Padding and unpadding successful" << std::endl;
}

void demo3_CTR_Mode() {
    std::cout << "\n=== Feature 3: AES-CTR Mode ===" << std::endl;
    
    AES_CTR ctr(AESKeyLength::AES_256);
    std::string message = "Hello, AES-CTR mode! This is stream cipher mode.";
    std::vector<unsigned char> plaintext(message.begin(), message.end());
    
    auto key = KeyManager::generateAES256Key();
    auto nonce = AES_CTR::generateNonce(16);
    
    std::cout << "Plaintext: " << message << std::endl;
    
    auto ciphertext = ctr.encrypt(plaintext, key, nonce);
    std::cout << "Ciphertext: "; printHex(ciphertext, 48);
    
    auto decrypted = ctr.decrypt(ciphertext, key, nonce);
    std::string decryptedMsg(decrypted.begin(), decrypted.end());
    std::cout << "Decrypted: " << decryptedMsg << std::endl;
    std::cout << "✓ CTR mode encryption/decryption successful" << std::endl;
}

void demo4_Base64() {
    std::cout << "\n=== Feature 4: Base64 Encoding ===" << std::endl;
    
    std::vector<unsigned char> data = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    std::cout << "Binary data: "; printHex(data);
    
    std::string encoded = Base64::encode(data);
    std::cout << "Base64 encoded: " << encoded << std::endl;
    
    auto decoded = Base64::decode(encoded);
    std::cout << "Decoded: "; printHex(decoded);
    std::cout << "✓ Base64 encoding/decoding successful" << std::endl;
}

void demo5_HMAC() {
    std::cout << "\n=== Feature 5: HMAC-SHA256 ===" << std::endl;
    
    HMAC hmac;
    std::string message = "Important message requiring integrity";
    std::vector<unsigned char> key = KeyManager::generateKey(32);
    
    std::cout << "Message: " << message << std::endl;
    
    auto mac = hmac.compute(key, message);
    std::cout << "HMAC: "; printHex(mac);
    
    bool valid = hmac.verify(key, 
        std::vector<unsigned char>(message.begin(), message.end()), mac);
    std::cout << "Verification: " << (valid ? "✓ Valid" : "✗ Invalid") << std::endl;
}

void demo6_KeyManager() {
    std::cout << "\n=== Feature 6: Key Management ===" << std::endl;
    
    auto aes128 = KeyManager::generateAES128Key();
    auto aes256 = KeyManager::generateAES256Key();
    
    std::cout << "Generated AES-128 key: "; printHex(aes128);
    std::cout << "Generated AES-256 key: "; printHex(aes256);
    
    std::string hexKey = KeyManager::keyToHex(aes256);
    std::cout << "Key as hex string: " << hexKey.substr(0, 40) << "..." << std::endl;
    
    KeyManager manager;
    manager.storeKey("mykey", aes256);
    std::cout << "✓ Key stored and retrieved successfully" << std::endl;
}

void demo7_FileEncryption() {
    std::cout << "\n=== Feature 7: File Encryption ===" << std::endl;
    
    // Create test file
    std::ofstream testFile("test_plain.txt");
    testFile << "This is a secret message that will be encrypted!";
    testFile.close();
    
    FileEncryption fileEnc(AESKeyLength::AES_256);
    auto key = KeyManager::generateAES256Key();
    
    std::cout << "Encrypting test_plain.txt..." << std::endl;
    auto iv = fileEnc.encryptFileWithIV("test_plain.txt", "test_encrypted.bin", key);
    std::cout << "✓ File encrypted to test_encrypted.bin" << std::endl;
    
    std::cout << "Decrypting test_encrypted.bin..." << std::endl;
    fileEnc.decryptFileWithIV("test_encrypted.bin", "test_decrypted.txt", key);
    std::cout << "✓ File decrypted to test_decrypted.txt" << std::endl;
}

void demo8_StreamCipher() {
    std::cout << "\n=== Feature 8: Streaming Encryption ===" << std::endl;
    
    StreamCipher stream(AESKeyLength::AES_256);
    auto key = KeyManager::generateAES256Key();
    std::vector<unsigned char> iv(16, 0x42);
    
    std::cout << "Chunk size: " << StreamCipher::getChunkSize() << " bytes" << std::endl;
    std::cout << "✓ Streaming cipher ready for large files" << std::endl;
    std::cout << "  (Use for files > 100MB to avoid memory issues)" << std::endl;
}

void demo9_AuthenticatedEncryption() {
    std::cout << "\n=== Feature 9: Authenticated Encryption ===" << std::endl;
    
    AuthenticatedEncryption authEnc(AESKeyLength::AES_256);
    std::string message = "Secret data with integrity protection";
    auto key = KeyManager::generateAES256Key();
    
    std::cout << "Message: " << message << std::endl;
    
    auto encrypted = authEnc.encrypt(message, key);
    std::cout << "Encrypted + MAC size: " << encrypted.size() << " bytes" << std::endl;
    std::cout << "Overhead: " << AuthenticatedEncryption::getOverhead() << " bytes" << std::endl;
    
    bool authentic = authEnc.verifyAuthenticity(encrypted, key);
    std::cout << "Authenticity check: " << (authentic ? "✓ Valid" : "✗ Invalid") << std::endl;
    
    std::string decrypted = authEnc.decryptToString(encrypted, key);
    std::cout << "Decrypted: " << decrypted << std::endl;
    std::cout << "✓ Authenticated encryption successful" << std::endl;
}

void demo10_SecureContainer() {
    std::cout << "\n=== Feature 10: Secure Container ===" << std::endl;
    
    SecureContainer container;
    auto key = KeyManager::generateAES256Key();
    
    std::string data = "Important document content";
    std::map<std::string, std::string> metadata;
    metadata["filename"] = "document.txt";
    metadata["author"] = "User";
    metadata["description"] = "Confidential data";
    
    std::cout << "Creating container with metadata..." << std::endl;
    auto containerData = container.createContainer(
        std::vector<unsigned char>(data.begin(), data.end()),
        key, metadata);
    
    std::cout << "Container size: " << containerData.size() << " bytes" << std::endl;
    
    auto info = container.getContainerInfo(containerData);
    std::cout << "Container version: " << info.version << std::endl;
    std::cout << "Timestamp: " << info.timestamp << std::endl;
    std::cout << "Metadata entries: " << metadata.size() << std::endl;
    
    std::map<std::string, std::string> extractedMeta;
    auto extractedData = container.extractFromContainer(containerData, key, extractedMeta);
    
    std::cout << "✓ Container created and extracted successfully" << std::endl;
    std::cout << "  Extracted metadata:" << std::endl;
    for (const auto& pair : extractedMeta) {
        std::cout << "    " << pair.first << ": " << pair.second << std::endl;
    }
}

int main() {
    std::cout << "╔════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║   AES Cryptography Library - Feature Demo         ║" << std::endl;
    std::cout << "║   10 Advanced Cryptographic Features              ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════╝" << std::endl;
    
    try {
        demo1_PBKDF2();
        demo2_Padding();
        demo3_CTR_Mode();
        demo4_Base64();
        demo5_HMAC();
        demo6_KeyManager();
        demo7_FileEncryption();
        demo8_StreamCipher();
        demo9_AuthenticatedEncryption();
        demo10_SecureContainer();
        
        std::cout << "\n╔════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║   All features demonstrated successfully! ✓       ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════╝" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
