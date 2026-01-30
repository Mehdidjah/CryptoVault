#ifndef _AUTHENTICATEDENCRYPTION_H_
#define _AUTHENTICATEDENCRYPTION_H_

#include "AES.h"
#include "HMAC.h"
#include <vector>
#include <string>

class AuthenticatedEncryption {
private:
    AES* aes;
    HMAC hmac;
    AESKeyLength keyLength;
    
    void deriveKeys(const std::vector<unsigned char>& masterKey,
                   std::vector<unsigned char>& encKey,
                   std::vector<unsigned char>& macKey);

public:
    explicit AuthenticatedEncryption(const AESKeyLength keyLength = AESKeyLength::AES_256);
    
    ~AuthenticatedEncryption();
    
    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& plaintext,
                                      const std::vector<unsigned char>& masterKey);
    
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& authenticatedCiphertext,
                                      const std::vector<unsigned char>& masterKey);
    
    std::vector<unsigned char> encrypt(const std::string& plaintext,
                                      const std::vector<unsigned char>& masterKey);
    
    std::string decryptToString(const std::vector<unsigned char>& authenticatedCiphertext,
                               const std::vector<unsigned char>& masterKey);
    
    bool verifyAuthenticity(const std::vector<unsigned char>& authenticatedCiphertext,
                           const std::vector<unsigned char>& masterKey);
    
    static constexpr size_t getOverhead() {
        return 16 + 32;
    }
};

#endif
