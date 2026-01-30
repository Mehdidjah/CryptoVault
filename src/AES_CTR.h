#ifndef _AES_CTR_H_
#define _AES_CTR_H_

#include "AES.h"
#include <vector>

class AES_CTR {
private:
    AES* aes;
    AESKeyLength keyLength;
    
    void incrementCounter(unsigned char* counter, size_t len);
    
    void xorBytes(const unsigned char* a, const unsigned char* b,
                  unsigned char* result, size_t len);

public:
    explicit AES_CTR(const AESKeyLength keyLength = AESKeyLength::AES_256);
    
    ~AES_CTR();
    
    unsigned char* encrypt(const unsigned char* plaintext, size_t plaintextLen,
                          const unsigned char* key,
                          const unsigned char* nonce, size_t nonceLen);
    
    unsigned char* decrypt(const unsigned char* ciphertext, size_t ciphertextLen,
                          const unsigned char* key,
                          const unsigned char* nonce, size_t nonceLen);
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                      const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& nonce);
    
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& ciphertext,
                                      const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& nonce);
    
    static std::vector<unsigned char> generateNonce(size_t length = 16);
};

#endif
