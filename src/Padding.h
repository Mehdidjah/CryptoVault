#ifndef _PADDING_H_
#define _PADDING_H_

#include <vector>
#include <stdexcept>

class Padding {
public:
    static constexpr size_t AES_BLOCK_SIZE = 16;
    
    static std::vector<unsigned char> addPKCS7(const std::vector<unsigned char>& data,
                                               size_t blockSize = AES_BLOCK_SIZE);
    
    static unsigned char* addPKCS7(const unsigned char* data, size_t dataLen,
                                   size_t blockSize, size_t& paddedLen);
    
    static std::vector<unsigned char> removePKCS7(const std::vector<unsigned char>& data,
                                                  size_t blockSize = AES_BLOCK_SIZE);
    
    static void removePKCS7(const unsigned char* data, size_t dataLen,
                           size_t blockSize, size_t& unpaddedLen);
    
    static bool validatePKCS7(const unsigned char* data, size_t dataLen, size_t blockSize);
};

#endif
