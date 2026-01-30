#include "KeyManager.h"
#include "PBKDF2.h"
#include <random>
#include <sstream>
#include <iomanip>
#include <cstring>

std::vector<unsigned char> KeyManager::generateKey(size_t keySize) {
    if (keySize != 16 && keySize != 24 && keySize != 32) {
        throw std::invalid_argument("Key size must be 16, 24, or 32 bytes");
    }
    
    std::vector<unsigned char> key(keySize);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < keySize; i++) {
        key[i] = static_cast<unsigned char>(dis(gen));
    }
    
    return key;
}

std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
KeyManager::deriveKeyFromPassword(const std::string& password,
                                 const std::vector<unsigned char>& salt,
                                 size_t keySize,
                                 unsigned int iterations) {
    PBKDF2 pbkdf2;
    
    std::vector<unsigned char> usedSalt = salt;
    if (usedSalt.empty()) {
        usedSalt = PBKDF2::generateSalt(16);
    }
    
    std::vector<unsigned char> key = pbkdf2.deriveKey(password, usedSalt, iterations, keySize);
    
    return std::make_pair(key, usedSalt);
}

void KeyManager::storeKey(const std::string& name, const std::vector<unsigned char>& key) {
    keyStore[name] = key;
}

std::vector<unsigned char> KeyManager::getKey(const std::string& name) const {
    auto it = keyStore.find(name);
    if (it != keyStore.end()) {
        return it->second;
    }
    return std::vector<unsigned char>();
}

bool KeyManager::hasKey(const std::string& name) const {
    return keyStore.find(name) != keyStore.end();
}

void KeyManager::removeKey(const std::string& name) {
    auto it = keyStore.find(name);
    if (it != keyStore.end()) {
        secureWipe(it->second);
        keyStore.erase(it);
    }
}

void KeyManager::clearAllKeys() {
    for (auto& pair : keyStore) {
        secureWipe(pair.second);
    }
    keyStore.clear();
}

std::string KeyManager::keyToHex(const std::vector<unsigned char>& key) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (unsigned char byte : key) {
        ss << std::setw(2) << static_cast<int>(byte);
    }
    return ss.str();
}

std::vector<unsigned char> KeyManager::hexToKey(const std::string& hex) {
    if (hex.length() % 2 != 0) {
        throw std::invalid_argument("Hex string must have even length");
    }
    
    std::vector<unsigned char> key;
    key.reserve(hex.length() / 2);
    
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
        key.push_back(byte);
    }
    
    return key;
}

void KeyManager::secureWipe(unsigned char* data, size_t len) {
    volatile unsigned char* ptr = data;
    for (size_t i = 0; i < len; i++) {
        ptr[i] = 0;
    }
}

void KeyManager::secureWipe(std::vector<unsigned char>& data) {
    secureWipe(data.data(), data.size());
}
