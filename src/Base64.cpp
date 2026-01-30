#include "Base64.h"
#include <stdexcept>

const std::string Base64::base64Chars = 
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789+/";

std::string Base64::encode(const unsigned char* data, size_t len) {
    std::string encoded;
    encoded.reserve(encodedSize(len));
    
    int val = 0;
    int valb = -6;
    
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) + data[i];
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(base64Chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    
    if (valb > -6) {
        encoded.push_back(base64Chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    
    while (encoded.size() % 4) {
        encoded.push_back('=');
    }
    
    return encoded;
}

std::string Base64::encode(const std::vector<unsigned char>& data) {
    return encode(data.data(), data.size());
}

std::vector<unsigned char> Base64::decode(const std::string& encoded) {
    std::vector<unsigned char> decoded;
    decoded.reserve(decodedSize(encoded));
    
    int val = 0;
    int valb = -8;
    
    for (unsigned char c : encoded) {
        if (c == '=') break;
        if (!isBase64(c)) {
            throw std::invalid_argument("Invalid Base64 character");
        }
        
        size_t pos = base64Chars.find(c);
        if (pos == std::string::npos) {
            throw std::invalid_argument("Invalid Base64 character");
        }
        
        val = (val << 6) + pos;
        valb += 6;
        
        if (valb >= 0) {
            decoded.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    
    return decoded;
}

unsigned char* Base64::decodeToArray(const std::string& encoded, size_t& outLen) {
    std::vector<unsigned char> decoded = decode(encoded);
    outLen = decoded.size();
    
    unsigned char* result = new unsigned char[outLen];
    std::copy(decoded.begin(), decoded.end(), result);
    
    return result;
}

bool Base64::isValidBase64(const std::string& str) {
    if (str.empty()) return false;
    if (str.length() % 4 != 0) return false;
    
    for (size_t i = 0; i < str.length(); i++) {
        char c = str[i];
        if (i >= str.length() - 2 && c == '=') {
            continue; // Allow padding
        }
        if (!isBase64(c)) {
            return false;
        }
    }
    
    return true;
}
