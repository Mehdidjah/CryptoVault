#ifndef _KEYMANAGER_H_
#define _KEYMANAGER_H_

#include <vector>
#include <string>
#include <map>

class KeyManager {
private:
    std::map<std::string, std::vector<unsigned char>> keyStore;
    
public:
    static std::vector<unsigned char> generateKey(size_t keySize);
    
    static std::vector<unsigned char> generateAES128Key() {
        return generateKey(16);
    }
    
    static std::vector<unsigned char> generateAES192Key() {
        return generateKey(24);
    }
    
    static std::vector<unsigned char> generateAES256Key() {
        return generateKey(32);
    }
    
    static std::pair<std::vector<unsigned char>, std::vector<unsigned char>>
    deriveKeyFromPassword(const std::string& password,
                         const std::vector<unsigned char>& salt = {},
                         size_t keySize = 32,
                         unsigned int iterations = 100000);
    
    void storeKey(const std::string& name, const std::vector<unsigned char>& key);
    
    std::vector<unsigned char> getKey(const std::string& name) const;
    
    bool hasKey(const std::string& name) const;
    
    void removeKey(const std::string& name);
    
    void clearAllKeys();
    
    static std::string keyToHex(const std::vector<unsigned char>& key);
    
    static std::vector<unsigned char> hexToKey(const std::string& hex);
    
    static void secureWipe(unsigned char* data, size_t len);
    static void secureWipe(std::vector<unsigned char>& data);
};

#endif
