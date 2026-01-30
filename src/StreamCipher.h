#ifndef _STREAMCIPHER_H_
#define _STREAMCIPHER_H_

#include "AES.h"
#include <string>
#include <fstream>
#include <functional>

class StreamCipher {
private:
    AES* aes;
    AESKeyLength keyLength;
    static constexpr size_t CHUNK_SIZE = 1024 * 1024;
    
    bool processFileInChunks(std::ifstream& inFile, std::ofstream& outFile,
                            const unsigned char* key, const unsigned char* iv,
                            bool encrypt);

public:
    explicit StreamCipher(const AESKeyLength keyLength = AESKeyLength::AES_256);
    
    ~StreamCipher();
    
    bool streamEncrypt(const std::string& inputFile,
                      const std::string& outputFile,
                      const std::vector<unsigned char>& key,
                      const std::vector<unsigned char>& iv,
                      std::function<void(int)> reportProgress = nullptr);
    
    bool streamDecrypt(const std::string& inputFile,
                      const std::string& outputFile,
                      const std::vector<unsigned char>& key,
                      const std::vector<unsigned char>& iv,
                      std::function<void(int)> reportProgress = nullptr);
    
    static size_t getChunkSize() { return CHUNK_SIZE; }
    
    static size_t customChunkSize;
};

#endif
