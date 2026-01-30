#include "HMAC.h"
#include <cstring>

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void HMAC::sha256Transform(uint32_t state[8], const unsigned char block[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;

    for (int i = 0; i < 16; i++) {
        w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) | 
               (block[i * 4 + 2] << 8) | block[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for (int i = 0; i < 64; i++) {
        t1 = h + sigma1(e) + ch(e, f, g) + K[i] + w[i];
        t2 = sigma0(a) + maj(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

void HMAC::sha256(const unsigned char* data, size_t len, unsigned char* hash) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    unsigned char block[64];
    size_t i = 0;
    
    while (i + 64 <= len) {
        memcpy(block, data + i, 64);
        sha256Transform(state, block);
        i += 64;
    }
    
    size_t remaining = len - i;
    memcpy(block, data + i, remaining);
    block[remaining] = 0x80;
    
    if (remaining >= 56) {
        memset(block + remaining + 1, 0, 64 - remaining - 1);
        sha256Transform(state, block);
        memset(block, 0, 56);
    } else {
        memset(block + remaining + 1, 0, 56 - remaining - 1);
    }
    
    uint64_t bitLen = len * 8;
    for (int j = 0; j < 8; j++) {
        block[63 - j] = bitLen >> (j * 8);
    }
    sha256Transform(state, block);
    
    for (int j = 0; j < 8; j++) {
        hash[j * 4] = state[j] >> 24;
        hash[j * 4 + 1] = state[j] >> 16;
        hash[j * 4 + 2] = state[j] >> 8;
        hash[j * 4 + 3] = state[j];
    }
}

void HMAC::compute(const unsigned char* key, size_t keyLen,
                   const unsigned char* message, size_t messageLen,
                   unsigned char* output) {
    unsigned char k[64];
    unsigned char k_ipad[64], k_opad[64];
    unsigned char tk[32];
    
    if (keyLen > 64) {
        sha256(key, keyLen, tk);
        key = tk;
        keyLen = 32;
    }
    
    memcpy(k, key, keyLen);
    memset(k + keyLen, 0, 64 - keyLen);
    
    for (int i = 0; i < 64; i++) {
        k_ipad[i] = k[i] ^ 0x36;
        k_opad[i] = k[i] ^ 0x5c;
    }
    
    unsigned char* inner = new unsigned char[64 + messageLen];
    memcpy(inner, k_ipad, 64);
    memcpy(inner + 64, message, messageLen);
    unsigned char innerHash[32];
    sha256(inner, 64 + messageLen, innerHash);
    delete[] inner;
    
    unsigned char outer[64 + 32];
    memcpy(outer, k_opad, 64);
    memcpy(outer + 64, innerHash, 32);
    sha256(outer, 96, output);
}

std::vector<unsigned char> HMAC::compute(const std::vector<unsigned char>& key,
                                         const std::vector<unsigned char>& message) {
    std::vector<unsigned char> output(SHA256_HASH_SIZE);
    compute(key.data(), key.size(), message.data(), message.size(), output.data());
    return output;
}

std::vector<unsigned char> HMAC::compute(const std::vector<unsigned char>& key,
                                         const std::string& message) {
    std::vector<unsigned char> output(SHA256_HASH_SIZE);
    compute(key.data(), key.size(),
            reinterpret_cast<const unsigned char*>(message.c_str()),
            message.length(), output.data());
    return output;
}

bool HMAC::verify(const unsigned char* key, size_t keyLen,
                 const unsigned char* message, size_t messageLen,
                 const unsigned char* expectedHmac) {
    unsigned char computedHmac[SHA256_HASH_SIZE];
    compute(key, keyLen, message, messageLen, computedHmac);
    return constantTimeCompare(computedHmac, expectedHmac, SHA256_HASH_SIZE);
}

bool HMAC::verify(const std::vector<unsigned char>& key,
                 const std::vector<unsigned char>& message,
                 const std::vector<unsigned char>& expectedHmac) {
    if (expectedHmac.size() != SHA256_HASH_SIZE) {
        return false;
    }
    return verify(key.data(), key.size(), message.data(), message.size(), expectedHmac.data());
}

bool HMAC::constantTimeCompare(const unsigned char* a, const unsigned char* b, size_t len) {
    unsigned char result = 0;
    for (size_t i = 0; i < len; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}
