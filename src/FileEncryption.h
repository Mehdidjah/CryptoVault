#ifndef _FILEENCRYPTION_H_
#define _FILEENCRYPTION_H_

#include "AES.h"
#include "Padding.h"
#include <string>
#include <vector>

class FileEncryption {
private:
    AES* aes;
    AESKeyLength keyLength;
    
    std::vector<unsigned char> readFile(const std::string& filename);
    
    void writeFile(const std::string& filename, const std::vector<unsigned char>& data);

public:
    explicit FileEncryption(const AESKeyLength keyLength = AESKeyLength::AES_256);
    
    ~FileEncryption();
    
    bool encryptFile(const std::string& inputFile,
                    const std::string& outputFile,
                    const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& iv);
    
    bool decryptFile(const std::string& inputFile,
                    const std::string& outputFile,
                    const std::vector<unsigned char>& key,
                    const std::vector<unsigned char>& iv);
    
    std::vector<unsigned char> encryptFileWithIV(const std::string& inputFile,
                                                 const std::string& outputFile,
                                                 const std::vector<unsigned char>& key);
    
    bool decryptFileWithIV(const std::string& inputFile,
                          const std::string& outputFile,
                          const std::vector<unsigned char>& key);
    
    static size_t getFileSize(const std::string& filename);
    
    static bool fileExists(const std::string& filename);
};

#endif
