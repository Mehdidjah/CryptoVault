#include "AES_CTR.h"
#include <cstring>
#include <random>

AES_CTR::AES_CTR(const AESKeyLength keyLength) : keyLength(keyLength) {
    aes = new AES(keyLength);
}

AES_CTR::~AES_CTR() {
    delete aes;
}

void AES_CTR::incrementCounter(unsigned char* counter, size_t len) {
    for (int i = len - 1; i >= 0; i--) {
        if (++counter[i] != 0) {
            break;
        }
    }
}

void AES_CTR::xorBytes(const unsigned char* a, const unsigned char* b,
                       unsigned char* result, size_t len) {
    for (size_t i = 0; i < len; i++) {
        result[i] = a[i] ^ b[i];
    }
}

unsigned char* AES_CTR::encrypt(const unsigned char* plaintext, size_t plaintextLen,
                                const unsigned char* key,
                                const unsigned char* nonce, size_t nonceLen) {
    if (nonceLen > 16) {
        throw std::invalid_argument("Nonce length cannot exceed 16 bytes");
    }
    
    unsigned char* ciphertext = new unsigned char[plaintextLen];
    unsigned char counter[16] = {0};
    
    memcpy(counter, nonce, nonceLen);
    
    size_t numBlocks = (plaintextLen + 15) / 16;
    
    for (size_t i = 0; i < numBlocks; i++) {
        unsigned char encryptedCounter[16];
        unsigned char* temp = aes->EncryptECB(counter, 16, key);
        memcpy(encryptedCounter, temp, 16);
        delete[] temp;
        
        size_t offset = i * 16;
        size_t blockSize = (offset + 16 <= plaintextLen) ? 16 : (plaintextLen - offset);
        xorBytes(plaintext + offset, encryptedCounter, ciphertext + offset, blockSize);
        
        incrementCounter(counter, 16);
    }
    
    return ciphertext;
}

unsigned char* AES_CTR::decrypt(const unsigned char* ciphertext, size_t ciphertextLen,
                                const unsigned char* key,
                                const unsigned char* nonce, size_t nonceLen) {
    return encrypt(ciphertext, ciphertextLen, key, nonce, nonceLen);
}

std::vector<unsigned char> AES_CTR::encrypt(const std::vector<unsigned char>& plaintext,
                                           const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& nonce) {
    unsigned char* result = encrypt(plaintext.data(), plaintext.size(),
                                   key.data(), nonce.data(), nonce.size());
    std::vector<unsigned char> output(result, result + plaintext.size());
    delete[] result;
    return output;
}

std::vector<unsigned char> AES_CTR::decrypt(const std::vector<unsigned char>& ciphertext,
                                           const std::vector<unsigned char>& key,
                                           const std::vector<unsigned char>& nonce) {
    return encrypt(ciphertext, key, nonce); // Same operation in CTR mode
}

std::vector<unsigned char> AES_CTR::generateNonce(size_t length) {
    std::vector<unsigned char> nonce(length);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < length; i++) {
        nonce[i] = static_cast<unsigned char>(dis(gen));
    }
    
    return nonce;
}
