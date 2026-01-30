#ifndef _HMAC_H_
#define _HMAC_H_

#include <vector>
#include <string>
#include <cstdint>

class HMAC {
private:
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
    static constexpr size_t SHA256_HASH_SIZE = 32;
    
    void compute(const unsigned char* key, size_t keyLen,
                const unsigned char* message, size_t messageLen,
                unsigned char* output);
    
    std::vector<unsigned char> compute(const std::vector<unsigned char>& key,
                                      const std::vector<unsigned char>& message);
    
    std::vector<unsigned char> compute(const std::vector<unsigned char>& key,
                                      const std::string& message);
    
    bool verify(const unsigned char* key, size_t keyLen,
               const unsigned char* message, size_t messageLen,
               const unsigned char* expectedHmac);
    
    bool verify(const std::vector<unsigned char>& key,
               const std::vector<unsigned char>& message,
               const std::vector<unsigned char>& expectedHmac);
    
    static bool constantTimeCompare(const unsigned char* a, const unsigned char* b, size_t len);
};

#endif
