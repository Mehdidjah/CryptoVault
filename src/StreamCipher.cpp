#include "StreamCipher.h"
#include "Padding.h"
#include <iostream>
#include <cstring>

size_t StreamCipher::customChunkSize = StreamCipher::CHUNK_SIZE;

StreamCipher::StreamCipher(const AESKeyLength keyLength) : keyLength(keyLength) {
    aes = new AES(keyLength);
}

StreamCipher::~StreamCipher() {
    delete aes;
}

bool StreamCipher::streamEncrypt(const std::string& inputFile,
                                const std::string& outputFile,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                std::function<void(int)> reportProgress) {
    try {
        std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
        if (!inFile.is_open()) {
            std::cerr << "Cannot open input file: " << inputFile << std::endl;
            return false;
        }
        
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);
        
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Cannot create output file: " << outputFile << std::endl;
            return false;
        }
        
        size_t chunkSize = (customChunkSize / 16) * 16; // Ensure multiple of 16
        std::vector<unsigned char> chunk(chunkSize);
        std::vector<unsigned char> prevBlock(iv.begin(), iv.end());
        
        size_t totalRead = 0;
        bool isLastChunk = false;
        
        while (!inFile.eof()) {
            inFile.read(reinterpret_cast<char*>(chunk.data()), chunkSize);
            std::streamsize bytesRead = inFile.gcount();
            
            if (bytesRead == 0) break;
            
            totalRead += bytesRead;
            isLastChunk = (totalRead >= fileSize);
            
            std::vector<unsigned char> chunkData(chunk.begin(), chunk.begin() + bytesRead);
            
            if (isLastChunk) {
                chunkData = Padding::addPKCS7(chunkData);
            } else if (chunkData.size() % 16 != 0) {
                size_t padding = 16 - (chunkData.size() % 16);
                chunkData.resize(chunkData.size() + padding, 0);
            }
            
            std::vector<unsigned char> encrypted = aes->EncryptCBC(chunkData, key, prevBlock);
            
            if (encrypted.size() >= 16) {
                prevBlock.assign(encrypted.end() - 16, encrypted.end());
            }
            
            outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
            
            if (reportProgress && fileSize > 0) {
                int percent = static_cast<int>((totalRead * 100) / fileSize);
                reportProgress(percent);
            }
        }
        
        inFile.close();
        outFile.close();
        
        if (reportProgress) {
            reportProgress(100);
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Stream encryption error: " << e.what() << std::endl;
        return false;
    }
}

bool StreamCipher::streamDecrypt(const std::string& inputFile,
                                const std::string& outputFile,
                                const std::vector<unsigned char>& key,
                                const std::vector<unsigned char>& iv,
                                std::function<void(int)> reportProgress) {
    try {
        std::ifstream inFile(inputFile, std::ios::binary | std::ios::ate);
        if (!inFile.is_open()) {
            std::cerr << "Cannot open input file: " << inputFile << std::endl;
            return false;
        }
        
        size_t fileSize = inFile.tellg();
        inFile.seekg(0, std::ios::beg);
        
        std::ofstream outFile(outputFile, std::ios::binary);
        if (!outFile.is_open()) {
            std::cerr << "Cannot create output file: " << outputFile << std::endl;
            return false;
        }
        
        size_t chunkSize = (customChunkSize / 16) * 16;
        std::vector<unsigned char> chunk(chunkSize);
        std::vector<unsigned char> prevBlock(iv.begin(), iv.end());
        
        size_t totalRead = 0;
        std::vector<unsigned char> lastDecrypted;
        
        while (!inFile.eof()) {
            inFile.read(reinterpret_cast<char*>(chunk.data()), chunkSize);
            std::streamsize bytesRead = inFile.gcount();
            
            if (bytesRead == 0) break;
            
            totalRead += bytesRead;
            bool isLastChunk = inFile.eof();
            
            std::vector<unsigned char> chunkData(chunk.begin(), chunk.begin() + bytesRead);
            
            std::vector<unsigned char> decrypted = aes->DecryptCBC(chunkData, key, prevBlock);
            
            if (chunkData.size() >= 16) {
                prevBlock.assign(chunkData.end() - 16, chunkData.end());
            }
            
            if (!lastDecrypted.empty()) {
                outFile.write(reinterpret_cast<const char*>(lastDecrypted.data()),
                            lastDecrypted.size());
            }
            
            lastDecrypted = decrypted;
            
            if (reportProgress && fileSize > 0) {
                int percent = static_cast<int>((totalRead * 100) / fileSize);
                reportProgress(percent);
            }
        }
        
        if (!lastDecrypted.empty()) {
            std::vector<unsigned char> unpadded = Padding::removePKCS7(lastDecrypted);
            outFile.write(reinterpret_cast<const char*>(unpadded.data()), unpadded.size());
        }
        
        inFile.close();
        outFile.close();
        
        if (reportProgress) {
            reportProgress(100);
        }
        
        return true;
    } catch (const std::exception& e) {
        std::cerr << "Stream decryption error: " << e.what() << std::endl;
        return false;
    }
}
