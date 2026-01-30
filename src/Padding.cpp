#include "Padding.h"
#include <cstring>

std::vector<unsigned char> Padding::addPKCS7(const std::vector<unsigned char>& data,
                                             size_t blockSize) {
    if (blockSize == 0 || blockSize > 255) {
        throw std::invalid_argument("Block size must be between 1 and 255");
    }
    
    size_t padding = blockSize - (data.size() % blockSize);
    std::vector<unsigned char> padded(data.size() + padding);
    
    std::copy(data.begin(), data.end(), padded.begin());
    
    for (size_t i = data.size(); i < padded.size(); i++) {
        padded[i] = static_cast<unsigned char>(padding);
    }
    
    return padded;
}

unsigned char* Padding::addPKCS7(const unsigned char* data, size_t dataLen,
                                 size_t blockSize, size_t& paddedLen) {
    if (blockSize == 0 || blockSize > 255) {
        throw std::invalid_argument("Block size must be between 1 and 255");
    }
    
    size_t padding = blockSize - (dataLen % blockSize);
    paddedLen = dataLen + padding;
    
    unsigned char* padded = new unsigned char[paddedLen];
    memcpy(padded, data, dataLen);
    
    for (size_t i = dataLen; i < paddedLen; i++) {
        padded[i] = static_cast<unsigned char>(padding);
    }
    
    return padded;
}

std::vector<unsigned char> Padding::removePKCS7(const std::vector<unsigned char>& data,
                                                size_t blockSize) {
    if (data.empty()) {
        throw std::invalid_argument("Cannot remove padding from empty data");
    }
    
    if (data.size() % blockSize != 0) {
        throw std::invalid_argument("Data length must be multiple of block size");
    }
    
    unsigned char paddingValue = data.back();
    
    if (paddingValue == 0 || paddingValue > blockSize) {
        throw std::invalid_argument("Invalid padding");
    }
    
    size_t paddingStart = data.size() - paddingValue;
    for (size_t i = paddingStart; i < data.size(); i++) {
        if (data[i] != paddingValue) {
            throw std::invalid_argument("Invalid padding bytes");
        }
    }
    
    return std::vector<unsigned char>(data.begin(), data.begin() + paddingStart);
}

void Padding::removePKCS7(const unsigned char* data, size_t dataLen,
                         size_t blockSize, size_t& unpaddedLen) {
    if (dataLen == 0) {
        throw std::invalid_argument("Cannot remove padding from empty data");
    }
    
    if (dataLen % blockSize != 0) {
        throw std::invalid_argument("Data length must be multiple of block size");
    }
    
    unsigned char paddingValue = data[dataLen - 1];
    
    if (paddingValue == 0 || paddingValue > blockSize) {
        throw std::invalid_argument("Invalid padding");
    }
    
    size_t paddingStart = dataLen - paddingValue;
    for (size_t i = paddingStart; i < dataLen; i++) {
        if (data[i] != paddingValue) {
            throw std::invalid_argument("Invalid padding bytes");
        }
    }
    
    unpaddedLen = paddingStart;
}

bool Padding::validatePKCS7(const unsigned char* data, size_t dataLen, size_t blockSize) {
    if (dataLen == 0 || dataLen % blockSize != 0) {
        return false;
    }
    
    unsigned char paddingValue = data[dataLen - 1];
    
    if (paddingValue == 0 || paddingValue > blockSize) {
        return false;
    }
    
    size_t paddingStart = dataLen - paddingValue;
    for (size_t i = paddingStart; i < dataLen; i++) {
        if (data[i] != paddingValue) {
            return false;
        }
    }
    
    return true;
}
