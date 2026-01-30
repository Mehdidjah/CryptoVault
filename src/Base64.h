#ifndef _BASE64_H_
#define _BASE64_H_

#include <string>
#include <vector>

class Base64 {
private:
    static const std::string base64Chars;
    
    static inline bool isBase64(unsigned char c) {
        return (isalnum(c) || (c == '+') || (c == '/'));
    }

public:
    static std::string encode(const unsigned char* data, size_t len);
    
    static std::string encode(const std::vector<unsigned char>& data);
    
    static std::vector<unsigned char> decode(const std::string& encoded);
    
    static unsigned char* decodeToArray(const std::string& encoded, size_t& outLen);
    
    static bool isValidBase64(const std::string& str);
    
    static size_t encodedSize(size_t dataLen) {
        return ((dataLen + 2) / 3) * 4;
    }
    
    static size_t decodedSize(const std::string& encoded) {
        size_t len = encoded.length();
        size_t padding = 0;
        if (len >= 2 && encoded[len - 1] == '=') padding++;
        if (len >= 2 && encoded[len - 2] == '=') padding++;
        return (len * 3) / 4 - padding;
    }
};

#endif
