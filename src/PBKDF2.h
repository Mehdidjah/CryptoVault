#ifndef _PBKDF2_H_
#define _PBKDF2_H_

#include <cstring>
#include <vector>
#include <stdexcept>

class PBKDF2 {
private:
    void hmacSha256(const unsigned char* key, size_t keyLen,
                    const unsigned char* data, size_t dataLen,
                    unsigned char* output);
    
    void sha256(const unsigned char* data, size_t len, unsigned char* hash);
    void sha256Transform(uint32_t state[8], const unsigned char block[64]);
    
    uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
    uint32_t ch(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (~x & z); }
    uint32_t maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) ^ (x & z) ^ (y & z); }
    uint32_t sigma0(uint32_t x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
    uint32_t sigma1(uint32_t x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
    uint32_t gamma0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
    uint32_t gamma1(uint32_t x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }

public:
    std::vector<unsigned char> deriveKey(const unsigned char* password, size_t passwordLen,
                                        const unsigned char* salt, size_t saltLen,
                                        unsigned int iterations, size_t keyLen);
    
    std::vector<unsigned char> deriveKey(const std::string& password,
                                        const std::vector<unsigned char>& salt,
                                        unsigned int iterations, size_t keyLen);
    
    static std::vector<unsigned char> generateSalt(size_t length = 16);
};

#endif
