#include "AuthenticatedEncryption.h"
#include "Padding.h"
#include "PBKDF2.h"
#include <random>
#include <cstring>

AuthenticatedEncryption::AuthenticatedEncryption(const AESKeyLength keyLength) 
    : keyLength(keyLength) {
    aes = new AES(keyLength);
}

AuthenticatedEncryption::~AuthenticatedEncryption() {
    delete aes;
}

void AuthenticatedEncryption::deriveKeys(const std::vector<unsigned char>& masterKey,
                                        std::vector<unsigned char>& encKey,
                                        std::vector<unsigned char>& macKey) {
    HMAC hmac;
    
    std::string encLabel = "encryption";
    encKey = hmac.compute(masterKey, encLabel);
    
    std::string macLabel = "authentication";
    macKey = hmac.compute(masterKey, macLabel);
}

std::vector<unsigned char> AuthenticatedEncryption::encrypt(
    const std::vector<unsigned char>& plaintext,
    const std::vector<unsigned char>& masterKey) {
    
    std::vector<unsigned char> encKey, macKey;
    deriveKeys(masterKey, encKey, macKey);
    
    std::vector<unsigned char> iv(16);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < 16; i++) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
    
    std::vector<unsigned char> padded = Padding::addPKCS7(plaintext);
    
    std::vector<unsigned char> ciphertext = aes->EncryptCBC(padded, encKey, iv);
    
    std::vector<unsigned char> messageForMac;
    messageForMac.reserve(16 + ciphertext.size());
    messageForMac.insert(messageForMac.end(), iv.begin(), iv.end());
    messageForMac.insert(messageForMac.end(), ciphertext.begin(), ciphertext.end());
    
    std::vector<unsigned char> mac = hmac.compute(macKey, messageForMac);
    
    std::vector<unsigned char> result;
    result.reserve(16 + ciphertext.size() + 32);
    result.insert(result.end(), iv.begin(), iv.end());
    result.insert(result.end(), ciphertext.begin(), ciphertext.end());
    result.insert(result.end(), mac.begin(), mac.end());
    
    return result;
}

std::vector<unsigned char> AuthenticatedEncryption::decrypt(
    const std::vector<unsigned char>& authenticatedCiphertext,
    const std::vector<unsigned char>& masterKey) {
    
    if (authenticatedCiphertext.size() < 48) {
        throw std::runtime_error("Invalid authenticated ciphertext: too short");
    }
    
    std::vector<unsigned char> encKey, macKey;
    deriveKeys(masterKey, encKey, macKey);
    
    std::vector<unsigned char> iv(authenticatedCiphertext.begin(),
                                  authenticatedCiphertext.begin() + 16);
    std::vector<unsigned char> mac(authenticatedCiphertext.end() - 32,
                                   authenticatedCiphertext.end());
    std::vector<unsigned char> ciphertext(authenticatedCiphertext.begin() + 16,
                                         authenticatedCiphertext.end() - 32);
    
    std::vector<unsigned char> messageForMac;
    messageForMac.reserve(16 + ciphertext.size());
    messageForMac.insert(messageForMac.end(), iv.begin(), iv.end());
    messageForMac.insert(messageForMac.end(), ciphertext.begin(), ciphertext.end());
    
    if (!hmac.verify(macKey, messageForMac, mac)) {
        throw std::runtime_error("Authentication failed: HMAC verification failed");
    }
    
    std::vector<unsigned char> padded = aes->DecryptCBC(ciphertext, encKey, iv);
    
    std::vector<unsigned char> plaintext = Padding::removePKCS7(padded);
    
    return plaintext;
}

std::vector<unsigned char> AuthenticatedEncryption::encrypt(
    const std::string& plaintext,
    const std::vector<unsigned char>& masterKey) {
    
    std::vector<unsigned char> data(plaintext.begin(), plaintext.end());
    return encrypt(data, masterKey);
}

std::string AuthenticatedEncryption::decryptToString(
    const std::vector<unsigned char>& authenticatedCiphertext,
    const std::vector<unsigned char>& masterKey) {
    
    std::vector<unsigned char> plaintext = decrypt(authenticatedCiphertext, masterKey);
    return std::string(plaintext.begin(), plaintext.end());
}

bool AuthenticatedEncryption::verifyAuthenticity(
    const std::vector<unsigned char>& authenticatedCiphertext,
    const std::vector<unsigned char>& masterKey) {
    
    try {
        if (authenticatedCiphertext.size() < 48) {
            return false;
        }
        
        std::vector<unsigned char> encKey, macKey;
        deriveKeys(masterKey, encKey, macKey);
        
        std::vector<unsigned char> mac(authenticatedCiphertext.end() - 32,
                                       authenticatedCiphertext.end());
        
        std::vector<unsigned char> messageForMac(authenticatedCiphertext.begin(),
                                                authenticatedCiphertext.end() - 32);
        
        return hmac.verify(macKey, messageForMac, mac);
    } catch (...) {
        return false;
    }
}
